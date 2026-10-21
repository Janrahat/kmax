"""KMAX command line interface.

Subcommands
-----------
``scan``      host discovery across IPs and CIDRs
``ports``     port scan with banner grabbing and exposure analysis
``dns``       DNS records, AXFR check and subdomain enumeration
``web``       HTTP headers, redirects and the TLS certificate
``sysinfo``   local system intelligence and posture
``report``    summarise one or more saved JSON reports
``shell``     interactive REPL over all of the above
``version``   print version and environment information

Global flags: ``--json`` (machine output), ``--quiet``, ``--no-color``,
``--debug``, ``--report PATH``, ``--format``.
"""

from __future__ import annotations

import argparse
import cmd
import json
import os
import shlex
import sys
import time
import traceback
from typing import Any, Sequence

from . import __version__
from .core import ui
from .core.context import Runtime
from .core.models import Finding, ScanMeta
from .core.report import Report, format_for_path, now_iso
from .core.utils import (
    TargetError,
    cli_snapshot,
    have,
    parse_ports,
    parse_target,
    run,
)

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_FOUND = 3
EXIT_PARTIAL = 4
EXIT_INTERRUPTED = 130

BANNER_SUBTITLE = "Kali Multi-tool eXplorer"


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kmax",
        description="KMAX - a modular, dependency-light security toolkit for Kali Linux.",
        epilog="Authorised testing only. Example: kmax ports 10.0.0.5 --top 1000 "
               "--report out/scan.html",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"kmax {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show debug detail while scanning")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress all human output (combine with --json)")
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="write machine-readable JSON to stdout")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colour (also honours NO_COLOR)")
    parser.add_argument("--debug", action="store_true",
                        help="print full tracebacks on unexpected errors")
    parser.add_argument("-o", "--report", metavar="PATH", default="",
                        help="write a report file (.html/.md/.json/.csv)")
    parser.add_argument("--format", dest="report_format", default="",
                        choices=["", "html", "markdown", "md", "json", "csv"],
                        help="override the report format instead of using the extension")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="per-probe timeout in seconds (default: 1.0)")
    parser.add_argument("--workers", type=int, default=200,
                        help="concurrent probes (default: 200)")
    parser.add_argument("--no-resolve", action="store_true",
                        help="skip hostname resolution")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # --- scan ---------------------------------------------------------- #
    scan = sub.add_parser("scan", help="discover live hosts on IPs or CIDRs",
                          description="ICMP + TCP host discovery with ARP enrichment.")
    scan.add_argument("targets", nargs="+", help="IP, hostname or CIDR (e.g. 10.0.0.0/24)")
    scan.add_argument("--tcp", metavar="PORTS",
                      help="TCP ports used as liveness probes (default: 80,443,22,445,3389,8080)")
    scan.add_argument("--no-ping", action="store_true", help="skip the ICMP probe")
    scan.add_argument("--nmap", action="store_true",
                      help="use nmap -sn when nmap is installed")

    # --- ports --------------------------------------------------------- #
    ports = sub.add_parser("ports", help="scan TCP/UDP ports with banner grabbing",
                           description="Asynchronous port scan plus exposure analysis.")
    ports.add_argument("target", help="IP, hostname or host:port")
    ports.add_argument("-p", "--ports", dest="port_spec", default="",
                       help="ports: 80,443,8000-8100 or common|top100|top1000|web|all")
    ports.add_argument("--top", type=int, default=0,
                       help="scan the N most common ports (e.g. --top 100)")
    ports.add_argument("--udp", action="store_true", help="probe UDP instead of TCP")
    ports.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    ports.add_argument("--no-service-detect", action="store_true",
                       help="use the port table only")
    ports.add_argument("--retries", type=int, default=0, help="retries per port")

    # --- dns ----------------------------------------------------------- #
    dns = sub.add_parser("dns", help="enumerate DNS records, AXFR and subdomains",
                         description="DNS records, zone-transfer check, subdomain brute force.")
    dns.add_argument("domain", help="domain name, e.g. example.com")
    dns.add_argument("--types", default="",
                     help="comma-separated record types (default: A,AAAA,MX,NS,TXT,SOA,CAA)")
    dns.add_argument("--dns-server", default="", help="query this resolver instead of /etc/resolv.conf")
    dns.add_argument("--axfr", action="store_true", help="attempt a zone transfer")
    dns.add_argument("--no-axfr", action="store_true", help="skip the zone-transfer check")
    dns.add_argument("-s", "--subdomains", action="store_true",
                     help="brute-force subdomains from the built-in wordlist")
    dns.add_argument("--wordlist", metavar="FILE", help="custom subdomain wordlist (one per line)")
    dns.add_argument("--no-wildcard-check", action="store_true",
                     help="skip wildcard DNS detection")

    # --- web ----------------------------------------------------------- #
    web = sub.add_parser("web", help="HTTP headers and TLS certificate analysis",
                         description="Fetch a URL and assess headers, redirects and TLS.")
    web.add_argument("url", help="URL, host or host:port")
    web.add_argument("--insecure", action="store_true",
                     help="do not verify the TLS chain (self-signed labs)")
    web.add_argument("--no-tls", action="store_true", help="skip the certificate inspection")
    web.add_argument("--no-redirect", action="store_true", help="do not follow redirects")
    web.add_argument("--user-agent", default="kmax/1.0 (+authorised security testing)",
                     help="override the User-Agent header")

    # --- sysinfo ------------------------------------------------------- #
    sysinfo = sub.add_parser("sysinfo", help="local system intelligence and posture",
                             description="OS, kernel, hardware, disks, interfaces and tool inventory.")
    sysinfo.add_argument("--public-ip", action="store_true",
                         help="look up the public egress address (needs internet)")
    sysinfo.add_argument("--tools", action="store_true", help="list the security-tool inventory")
    sysinfo.add_argument("--packages", action="store_true", help="list package-manager facts")

    # --- report -------------------------------------------------------- #
    report = sub.add_parser("report", help="summarise saved JSON reports",
                            description="Read one or more JSON reports written by kmax and "
                                        "print or re-export a combined summary.")
    report.add_argument("files", nargs="+", help="JSON report file(s)")
    report.add_argument("--out", metavar="PATH", default="",
                        help="write the combined report to this path")
    report.add_argument("--top", type=int, default=10,
                        help="how many findings to list (default: 10)")

    # --- shell --------------------------------------------------------- #
    sub.add_parser("shell", help="interactive KMAX prompt",
                   description="REPL exposing every command; type 'help' inside.")

    # --- version ------------------------------------------------------- #
    sub.add_parser("version", help="print version and environment information")
    return parser


def parser_for_shell() -> argparse.ArgumentParser:
    """Reuse the main parser inside the REPL (no help/version noise)."""
    return build_parser()


# --------------------------------------------------------------------------- #
# Runtime wiring
# --------------------------------------------------------------------------- #
def make_runtime(args: argparse.Namespace, argv: Sequence[str] | None = None) -> Runtime:
    return Runtime(
        quiet=getattr(args, "quiet", False),
        json_output=getattr(args, "json_output", False),
        verbose=getattr(args, "verbose", False),
        no_color=getattr(args, "no_color", False),
        timeout=getattr(args, "timeout", 1.0) or 1.0,
        workers=max(1, getattr(args, "workers", 200) or 200),
        resolve=not getattr(args, "no_resolve", False),
        use_nmap=getattr(args, "nmap", False),
        banners=not getattr(args, "no_banner", False),
        service_detect=not getattr(args, "no_service_detect", False),
        udp=getattr(args, "udp", False),
        verbose_errors=getattr(args, "debug", False),
        report_path=getattr(args, "report", "") or "",
        report_format=getattr(args, "report_format", "") or "",
        module=getattr(args, "command", "") or "",
        target=" ".join(getattr(args, "targets", []) or [getattr(args, "target", "") or
                                                        getattr(args, "domain", "") or
                                                        getattr(args, "url", "")]),
        argv=list(argv if argv is not None else sys.argv),
    )


def _emit_json(payload: Any) -> None:
    """Print JSON safely: no colour, no truncated floats."""
    sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n")


def _save_report(report: Report, runtime: Runtime, meta: ScanMeta) -> str:
    runtime.finish(report, meta)
    path = runtime.report_path
    fmt = runtime.report_format or format_for_path(path)
    saved = report.save(path, fmt)
    if not runtime.quiet:
        ui.ok(f"report written: {saved} ({fmt})")
    return saved


def _finish(runtime: Runtime, report: Report, meta: ScanMeta,
            payload: dict[str, Any]) -> int:
    """Common tail: save the report, print JSON / the summary."""
    payload["meta"] = {
        "tool": meta.tool, "version": meta.version, "module": meta.module,
        "target": meta.target, "started": meta.started,
        "duration_s": round(runtime.elapsed, 3),
        "host": meta.host, "user": meta.user, "elevated": meta.elevated,
        "command": meta.command,
    }
    payload["risk_score"] = report.risk_score()
    payload["severity"] = report.severity_counts()
    payload["findings"] = report.all_findings()

    saved = ""
    if runtime.report_path:
        saved = _save_report(report, runtime, meta)
        payload["report_path"] = saved

    if runtime.json_output:
        _emit_json(payload)
    elif not runtime.quiet:
        report.print_summary()
        if saved:
            ui.plain(f"  {ui.c('report', 'cyan')} : {saved}")

    critical = payload["severity"].get("critical", 0)
    return EXIT_PARTIAL if critical else EXIT_OK


# --------------------------------------------------------------------------- #
# Command implementations
# --------------------------------------------------------------------------- #
def cmd_scan(args: argparse.Namespace, runtime: Runtime) -> int:
    from .modules import netscan

    meta = runtime.make_meta("scan", " ".join(args.targets))
    report = Report(meta, title=f"KMAX host discovery - {meta.target}")
    payload: dict[str, Any] = {"module": "scan", "targets": args.targets}

    tcp_ports: tuple[int, ...] = netscan.DEFAULT_TCP_PROBES
    if args.tcp:
        tcp_ports = tuple(parse_ports(args.tcp))

    opts = netscan.SweepOptions(
        targets=list(args.targets),
        timeout=max(0.2, runtime.timeout),
        workers=runtime.workers,
        ping=not args.no_ping,
        tcp_ports=tcp_ports,
        use_nmap=runtime.use_nmap,
        resolve_names=runtime.resolve,
    )
    result = netscan.execute(opts)
    netscan.render(result, report)

    payload.update({
        "scanned": result.scanned,
        "method": result.method,
        "duration_s": result.elapsed_s,
        "hosts": [{
            "address": host.address, "hostname": host.hostname, "state": host.state,
            "mac": host.mac, "vendor": host.vendor, "latency_ms": host.latency_ms,
            "method": host.method,
        } for host in result.hosts],
    })
    report.note("hosts", payload["hosts"])
    return _finish(runtime, report, meta, payload)


def cmd_ports(args: argparse.Namespace, runtime: Runtime) -> int:
    from .modules import portscan

    try:
        target = parse_target(args.target, do_resolve=runtime.resolve)
    except TargetError as exc:
        ui.err(str(exc))
        return EXIT_USAGE

    if not target.address:
        ui.err(f"could not resolve {target.host!r}")
        return EXIT_NOT_FOUND

    try:
        port_list = parse_ports(args.port_spec or None, args.top or None)
    except TargetError as exc:
        ui.err(str(exc))
        return EXIT_USAGE

    meta = runtime.make_meta("ports", target.display())
    report = Report(meta, title=f"KMAX port scan - {target.display()}")
    payload: dict[str, Any] = {
        "module": "ports", "target": target.host, "address": target.address,
        "probed": len(port_list),
    }

    opts = portscan.PortOptions(
        host=target.address,
        ports=port_list,
        timeout=max(0.1, runtime.timeout),
        concurrency=max(1, runtime.workers),
        banners=runtime.banners,
        service_detect=runtime.service_detect,
        udp=args.udp,
        retries=max(0, args.retries),
    )
    result = portscan.execute(opts, host_ip=target.address)
    result.host = target.display()
    portscan.render(result, report)

    payload.update({
        "duration_s": result.elapsed_s,
        "method": result.method,
        "open_ports": [{
            "port": item.port, "protocol": item.protocol, "state": item.state,
            "service": item.service, "version": item.version,
            "banner": item.banner, "latency_ms": item.latency_ms,
        } for item in result.ports],
    })
    report.note("port_results", payload["open_ports"])
    return _finish(runtime, report, meta, payload)


def cmd_dns(args: argparse.Namespace, runtime: Runtime) -> int:
    from .modules import dnsenum

    record_types = tuple(
        part.strip().upper() for part in args.types.split(",") if part.strip()
    ) or dnsenum.DEFAULT_RECORD_TYPES

    wordlist: list[str] = []
    if args.subdomains:
        if args.wordlist:
            from .core.utils import read_lines

            wordlist = read_lines(args.wordlist)
            if not wordlist:
                ui.err(f"wordlist {args.wordlist!r} is empty or unreadable")
                return EXIT_USAGE
        else:
            wordlist = dnsenum.SUBDOMAIN_WORDLIST

    meta = runtime.make_meta("dns", args.domain)
    report = Report(meta, title=f"KMAX DNS intelligence - {args.domain}")
    payload: dict[str, Any] = {"module": "dns", "domain": args.domain,
                               "record_types": list(record_types)}

    opts = dnsenum.DNSOptions(
        domain=args.domain,
        record_types=record_types,
        resolver=args.dns_server,
        timeout=max(0.5, runtime.timeout * 3),
        do_axfr=not args.no_axfr,
        do_subdomains=bool(args.subdomains),
        wordlist=wordlist,
        workers=max(10, min(runtime.workers, 200)),
        wildcard_check=not args.no_wildcard_check,
    )
    try:
        result = dnsenum.execute(opts)
    except ValueError as exc:
        ui.err(str(exc))
        return EXIT_USAGE

    dnsenum.render(result, report)
    payload.update({
        "resolver": result.resolver,
        "backend": result.backend,
        "duration_s": result.elapsed_s,
        "nameservers": result.nameservers,
        "mail_servers": result.mail_servers,
        "addresses": result.addresses(),
        "wildcard": result.wildcard,
        "axfr_tested": result.axfr_tested,
        "axfr_records": result.axfr_records,
        "subdomains": [{"host": host, "address": address}
                       for host, address in result.subdomains],
        "records": [{"type": record.record_type, "value": record.value,
                     "ttl": record.ttl} for record in result.answers],
        "reverse": [{"address": address, "ptr": name} for address, name in result.reverse],
    })
    return _finish(runtime, report, meta, payload)


def cmd_web(args: argparse.Namespace, runtime: Runtime) -> int:
    from .modules import webscan

    meta = runtime.make_meta("web", args.url)
    report = Report(meta, title=f"KMAX web analysis - {args.url}")
    payload: dict[str, Any] = {"module": "web", "url": args.url}

    opts = webscan.WebOptions(
        url=args.url,
        timeout=max(2.0, runtime.timeout * 6),
        follow_redirects=not args.no_redirect,
        check_tls=not args.no_tls,
        user_agent=args.user_agent,
        insecure_label="insecure" if args.insecure else "",
    )
    try:
        result = webscan.execute(opts)
    except ValueError as exc:
        ui.err(str(exc))
        return EXIT_USAGE

    webscan.render(result, report)

    payload["targets"] = [{
        "url": outcome.url,
        "status": outcome.status,
        "reason": outcome.reason,
        "final_url": outcome.final_url,
        "server": outcome.server,
        "content_type": outcome.content_type,
        "title": outcome.title,
        "length": outcome.length,
        "elapsed_ms": outcome.elapsed_ms,
        "redirect_chain": outcome.redirect_chain,
        "headers": outcome.headers,
        "certificate": {
            "subject": outcome.cert.subject,
            "issuer": outcome.cert.issuer,
            "not_before": outcome.cert.not_before,
            "not_after": outcome.cert.not_after,
            "days_remaining": outcome.cert.days_remaining,
            "protocol": outcome.cert.protocol,
            "cipher": outcome.cert.cipher,
            "signature_algorithm": outcome.cert.signature_algorithm,
            "self_signed": outcome.cert.self_signed,
            "sans": outcome.cert.sans,
        } if outcome.cert else None,
    } for outcome in result.results]
    payload["duration_s"] = result.elapsed_s
    return _finish(runtime, report, meta, payload)


def cmd_sysinfo(args: argparse.Namespace, runtime: Runtime) -> int:
    from .modules import sysinfo

    meta = runtime.make_meta("sysinfo", "localhost")
    report = Report(meta, title="KMAX system information")
    payload: dict[str, Any] = {"module": "sysinfo"}

    opts = sysinfo.SysOptions(
        include_public_ip=bool(args.public_ip),
        include_tools=True,
        include_packages=bool(args.packages),
        timeout=max(2.0, runtime.timeout * 5),
    )
    result = sysinfo.execute(opts)
    sysinfo.render(result, report, show_tools=bool(args.tools),
                   show_packages=bool(args.packages))

    info = result.info
    payload.update({
        "duration_s": result.elapsed_s,
        "system": {
            "os": info.os_name, "kernel": info.kernel,
            "architecture": info.architecture, "hostname": info.hostname,
            "user": info.user, "elevated": info.elevated, "uptime": info.uptime,
            "boot_time": info.boot_time, "cpu_model": info.cpu_model,
            "cpu_cores": info.cpu_cores, "memory_total": info.mem_total,
            "memory_used": info.mem_used, "memory_percent": info.mem_percent,
            "disks": info.disks, "interfaces": info.interfaces,
            "gateway": info.gateway, "dns_servers": info.dns_servers,
            "public_ip": info.public_ip, "runtimes": info.runtimes,
            "packages": info.packages, "tools": info.tools,
        },
    })
    return _finish(runtime, report, meta, payload)


def cmd_report(args: argparse.Namespace, runtime: Runtime) -> int:
    metas: list[dict[str, Any]] = []
    combined = Report(ScanMeta(module="report", target=", ".join(args.files)),
                      title="KMAX combined report")
    total_findings: list[dict[str, Any]] = []
    missing: list[str] = []

    for path in args.files:
        if not os.path.isfile(path):
            missing.append(path)
            ui.warn(f"not found: {path}")
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            ui.warn(f"cannot read {path}: {exc}")
            missing.append(path)
            continue

        section = payload.get("report", {})
        meta = payload.get("meta", {})
        metas.append({
            "file": path,
            "title": section.get("title", ""),
            "module": meta.get("module", ""),
            "target": meta.get("target", ""),
            "generated": section.get("generated", ""),
            "risk_score": section.get("risk_score", 0),
            "severity": section.get("severity", {}),
        })
        findings = [
            {**row, "report": os.path.basename(path)}
            for row in (payload.get("sections") or [])
            if row.get("type") == "findings"
            for row in row.get("rows", [])
        ]
        total_findings.extend(findings)
        if findings:
            combined.findings([Finding(**{key: value for key, value in row.items()
                                          if key in Finding.__dataclass_fields__})
                               for row in findings],
                              f"{os.path.basename(path)} - findings")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "good": 5}
    total_findings.sort(key=lambda row: order.get(str(row.get("severity", "info")), 9))

    if metas:
        combined.table("Source reports",
                       ["File", "Module", "Target", "Generated", "Risk", "Findings"],
                       [[row["file"], row["module"], row["target"], row["generated"],
                         row["risk_score"], sum(row["severity"].values())]
                        for row in metas])

    if total_findings:
        combined.table(f"Top findings (showing {min(args.top, len(total_findings))})",
                       ["Severity", "Title", "Report"],
                       [[row.get("severity", "").upper(), row.get("title", ""),
                         row.get("report", "")] for row in total_findings[: args.top]])

    if not runtime.json_output and not runtime.quiet:
        ui.section("Report summary", "\u25c6")
        if metas:
            ui.table(["File", "Module", "Target", "Risk", "Findings"],
                     [[row["file"], row["module"], row["target"], row["risk_score"],
                       sum(row["severity"].values())] for row in metas])
        if total_findings:
            ui.section(f"Top {min(args.top, len(total_findings))} findings", "\u2691")
            for row in total_findings[: args.top]:
                ui.plain(f"  {ui.severity_tag(row.get('severity', 'info'))} "
                         f"{row.get('title', '')}")
            ui.plain(ui.c(f"  total findings: {len(total_findings)}", "gray"))
        if not metas:
            ui.warn("no readable JSON reports were supplied")

    payload: dict[str, Any] = {
        "module": "report",
        "reports": metas,
        "total_findings": len(total_findings),
        "top_findings": total_findings[: args.top],
        "unreadable": missing,
    }

    meta = combined.meta
    if args.out:
        runtime.report_path = args.out
        runtime.report_format = runtime.report_format or format_for_path(args.out)
    if runtime.report_path:
        payload["report_path"] = _save_report(combined, runtime, meta)

    if runtime.json_output:
        _emit_json(payload)
    if not metas:
        return EXIT_NOT_FOUND
    return EXIT_OK


def cmd_version(args: argparse.Namespace, runtime: Runtime) -> int:
    from .modules import sysinfo

    payload = {
        "tool": "kmax",
        "version": __version__,
        "python": sys.version.split()[0],
        "platform": sysinfo.os_name(),
        "kernel": sysinfo.platform.release(),
        "elevated": sysinfo.is_root(),
        "helpers": {name: ("available" if have(name) else "missing")
                    for name in ("nmap", "dig", "openssl", "ping", "ip", "curl")},
        "dns_backend": __import__("kmax.modules.dnsenum", fromlist=["x"]).backend_name(),
    }
    if runtime.json_output:
        _emit_json(payload)
    elif not runtime.quiet:
        ui.banner(BANNER_SUBTITLE, __version__)
        ui.kv([
            ("Tool", "kmax"),
            ("Version", __version__),
            ("Python", payload["python"]),
            ("Platform", f"{payload['platform']} / {payload['kernel']}"),
            ("Elevated", "yes" if payload["elevated"] else "no"),
            ("DNS backend", payload["dns_backend"]),
        ])
        ui.section("Optional helpers", "\u25c8")
        for name, state in payload["helpers"].items():
            tag = "good" if state == "available" else "low"
            ui.plain(f"  {ui.severity_tag(tag)} {name:<9} {state}")
        ui.plain()
        ui.plain(ui.c("  KMAX works without any of these; they only enrich some checks.", "gray"))
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Interactive shell
# --------------------------------------------------------------------------- #
class KmaxShell(cmd.Cmd):
    """Interactive prompt: every subcommand, plus ``set``, ``env`` and ``run``."""

    intro = ("\nKMAX interactive shell. Type 'help' for commands, 'help <cmd>' for "
             "details,\n'set json on' for machine output, 'env' to see the runtime, "
             "'exit' to leave.\n")

    def __init__(self, runtime: Runtime, argv: Sequence[str]) -> None:
        super().__init__()
        self.runtime = runtime
        self.argv = list(argv)
        self.parser = parser_for_shell()
        self.prompt = ui.c("kmax> ", "bcyan", "bold") if ui.color_enabled() else "kmax> "

    # -- helpers -------------------------------------------------------- #
    _GLOBAL_BOOL_FLAGS = {"-v", "--verbose", "-q", "--quiet", "--json",
                          "--no-color", "--debug", "--no-resolve"}
    _GLOBAL_VALUE_FLAGS = {"-o", "--report", "--format", "--timeout", "--workers"}

    def _split_globals(self, tokens: list[str]) -> tuple[list[str], list[str]]:
        """Hoist only *known* global flags; everything else stays with the command.

        Anything unknown (e.g. ``--no-banner``, ``--quick``) must stay after the
        subcommand, otherwise argparse rejects it as an unrecognised top-level
        option.
        """
        global_args: list[str] = []
        command_tokens: list[str] = []
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token in self._GLOBAL_BOOL_FLAGS:
                global_args.append(token)
            elif token in self._GLOBAL_VALUE_FLAGS:
                global_args.append(token)
                if index + 1 < len(tokens):
                    index += 1
                    global_args.append(tokens[index])
            else:
                command_tokens.append(token)
            index += 1
        return global_args, command_tokens

    def _run_line(self, line: str) -> None:
        tokens = shlex.split(line)
        if not tokens:
            return
        global_args, command_tokens = self._split_globals(tokens)
        try:
            args = self.parser.parse_args(global_args + command_tokens)
        except SystemExit:
            return
        runtime = make_runtime(args, self.argv)
        runtime.quiet = self.runtime.quiet
        runtime.json_output = self.runtime.json_output
        runtime.report_path = self.runtime.report_path
        runtime.report_format = self.runtime.report_format
        runtime.verbose = self.runtime.verbose
        code = dispatch(args, runtime, shell=True)
        self.last_exit = code

    # -- commands ------------------------------------------------------- #
    def do_scan(self, line: str) -> None:
        """scan <targets...> [--tcp PORTS] [--no-ping] [--nmap]"""
        self._run_line(f"scan {line}")

    def do_ports(self, line: str) -> None:
        """ports <target> [-p SPEC] [--top N] [--udp] [--no-banner]"""
        self._run_line(f"ports {line}")

    def do_dns(self, line: str) -> None:
        """dns <domain> [--types A,MX] [--axfr] [-s] [--dns-server IP]"""
        self._run_line(f"dns {line}")

    def do_web(self, line: str) -> None:
        """web <url> [--insecure] [--no-tls] [--no-redirect]"""
        self._run_line(f"web {line}")

    def do_sysinfo(self, line: str) -> None:
        """sysinfo [--public-ip] [--tools] [--packages]"""
        self._run_line(f"sysinfo {line}")

    def do_report(self, line: str) -> None:
        """report <file.json> [<file2.json> ...] [--out combined.html] [--top N]"""
        self._run_line(f"report {line}")

    def do_version(self, line: str) -> None:
        """version - print version and environment information"""
        self._run_line("version")

    def do_set(self, line: str) -> None:
        """set <key> <value> - json|quiet|report|format|timeout|workers|verbose"""
        parts = shlex.split(line)
        if len(parts) != 2:
            ui.warn("usage: set <json|quiet|report|format|timeout|workers|verbose> <value>")
            return
        key, value = parts[0].lower(), parts[1]
        truthy = value.lower() in ("on", "true", "yes", "1")
        if key == "json":
            self.runtime.json_output = truthy
        elif key == "quiet":
            self.runtime.quiet = truthy
            ui.configure(quiet=truthy)
        elif key == "verbose":
            self.runtime.verbose = truthy
            os.environ["KMAX_DEBUG"] = "1" if truthy else ""
        elif key == "report":
            self.runtime.report_path = value
        elif key == "format":
            self.runtime.report_format = value
        elif key == "timeout":
            self.runtime.timeout = float(value)
        elif key == "workers":
            self.runtime.workers = int(value)
        else:
            ui.warn(f"unknown setting: {key}")
            return
        ui.ok(f"{key} = {value}")

    def do_env(self, line: str) -> None:
        """env - show the current runtime settings"""
        ui.section("Runtime", "\u25c6")
        ui.kv([
            ("json", self.runtime.json_output),
            ("quiet", self.runtime.quiet),
            ("verbose", self.runtime.verbose),
            ("timeout", self.runtime.timeout),
            ("workers", self.runtime.workers),
            ("report", self.runtime.report_path or "(none)"),
            ("format", self.runtime.report_format or "(by extension)"),
            ("cwd", os.getcwd()),
        ])

    def do_run(self, line: str) -> None:
        """run <shell command> - execute a system command (use with care)"""
        if not line.strip():
            ui.warn("usage: run <command>")
            return
        if not self.runtime.quiet:
            ui.info(f"$ {line}")
        code, out, err = run(shlex.split(line), timeout=120)
        if out:
            ui.plain(out.rstrip())
        if err and not out:
            ui.plain(ui.c(err.rstrip(), "gray"))
        ui.plain(ui.c(f"(exit {code})", "gray"))

    def do_exit(self, line: str) -> bool:
        """exit - leave the shell"""
        ui.plain(ui.c("bye.", "gray"))
        return True

    do_EOF = do_exit  # Ctrl-D leaves the shell

    def default(self, line: str) -> None:
        if not line.strip():
            return
        ui.warn(f"unknown command: {line.split()[0]!r} (type 'help')")

    def emptyline(self) -> bool:
        return False

    def postcmd(self, stop: bool, line: str) -> bool:
        return stop


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #
_COMMANDS = {
    "scan": cmd_scan,
    "ports": cmd_ports,
    "dns": cmd_dns,
    "web": cmd_web,
    "sysinfo": cmd_sysinfo,
    "report": cmd_report,
    "version": cmd_version,
}


def dispatch(args: argparse.Namespace, runtime: Runtime, shell: bool = False) -> int:
    handler = _COMMANDS.get(args.command or "")
    if handler is None:
        if shell:
            ui.warn("no command given")
            return EXIT_USAGE
        build_parser().print_help()
        return EXIT_USAGE
    try:
        return handler(args, runtime)
    except KeyboardInterrupt:
        ui.warn("interrupted by user")
        return EXIT_INTERRUPTED
    except TargetError as exc:
        ui.err(str(exc))
        return EXIT_USAGE
    except ValueError as exc:
        ui.err(str(exc))
        return EXIT_USAGE
    except Exception as exc:  # pragma: no cover - last-resort guard
        ui.err(f"unexpected error: {type(exc).__name__}: {exc}")
        if runtime.verbose_errors or os.environ.get("KMAX_DEBUG"):
            traceback.print_exc()
        else:
            ui.plain(ui.c("  re-run with --debug for the full traceback", "gray"))
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``kmax`` console script."""
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "shell":
        runtime = make_runtime(args, ["kmax", "shell"])
        ui.configure(no_color=args.no_color, quiet=False)
        ui.banner(BANNER_SUBTITLE, __version__)
        shell = KmaxShell(runtime, ["kmax"])
        try:
            shell.cmdloop()
        except KeyboardInterrupt:
            ui.plain()
            ui.warn("interrupted")
            return EXIT_INTERRUPTED
        return getattr(shell, "last_exit", EXIT_OK)

    if args.debug or args.verbose:
        os.environ["KMAX_DEBUG"] = "1"

    runtime = make_runtime(args, ["kmax"] + argv)
    ui.configure(no_color=args.no_color, quiet=args.quiet or args.json_output)

    if args.command is None:
        ui.banner(BANNER_SUBTITLE, __version__)
        parser.print_help()
        return EXIT_USAGE

    if args.command != "version" and not args.json_output and not args.quiet:
        ui.banner(BANNER_SUBTITLE, __version__)
    if args.verbose and not args.quiet:
        ui.debug(f"argv: {cli_snapshot(['kmax'] + argv)}")
        ui.debug(f"python: {sys.version.split()[0]} on {sys.platform}")

    return dispatch(args, runtime)
