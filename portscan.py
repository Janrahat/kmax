"""Asynchronous TCP/UDP port scanner with banner grabbing and fingerprinting.

Design notes
------------
* One ``asyncio`` event loop drives every probe, bounded by a semaphore, so a
  1000-port scan or a whole /24 needs no threads and no elevated privileges.
* Banner grabbing is protocol-aware: an HTTP ``HEAD`` is sent to web ports, a
  TLS handshake is attempted on TLS ports, otherwise the service is simply
  invited to speak first.
* UDP is best-effort by nature, and the module says so instead of pretending.
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from ..core import ui
from ..core.models import Finding, PortResult
from ..core.utils import WEB_PORTS, is_private, service_for

__all__ = ["PortOptions", "PortScanResult", "execute", "render", "fingerprint",
           "analyse", "summarise", "RISKY_PORTS", "TLS_PORTS", "grab_banner"]

TLS_PORTS: tuple[int, ...] = (443, 465, 636, 853, 993, 995, 8443, 9443, 10443)


@dataclass
class PortOptions:
    host: str
    ports: list[int]
    timeout: float = 1.0
    concurrency: int = 400
    banners: bool = True
    service_detect: bool = True
    udp: bool = False
    retries: int = 0


@dataclass
class PortScanResult:
    host: str
    address: str = ""
    ports: list[PortResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    elapsed_s: float = 0.0
    probed: int = 0
    method: str = "tcp-connect"


# --------------------------------------------------------------------------- #
# Fingerprinting
# --------------------------------------------------------------------------- #
# (regex, service, version template - {0}, {1} are substituted from groups)
_BANNER_RULES: list[tuple[str, str, str]] = [
    (r"SSH-\d+\.\d+-OpenSSH[_ ]?([\w.p-]+)?", "ssh", "OpenSSH {0}"),
    (r"SSH-\d+\.\d+-dropbear[_ ]?([\w.]+)?", "ssh", "Dropbear {0}"),
    (r"SSH-\d+\.\d+-([\w.]+)", "ssh", "{0}"),
    (r"220[- ].*?Microsoft ESMTP", "smtp", "Microsoft Exchange"),
    (r"220[- ].*?Postfix", "smtp", "Postfix"),
    (r"220[- ].*?Exim ([\w.]+)", "smtp", "Exim {0}"),
    (r"220[- ].*?Sendmail ([\w./]+)", "smtp", "Sendmail {0}"),
    (r"220[- ].*?ESMTP", "smtp", "SMTP"),
    (r"\+OK.*?(Dovecot|Courier)", "pop3", "POP3 {0}"),
    (r"\* OK.*?(Dovecot|Courier)", "imap", "IMAP {0}"),
    (r"220[- ].*?vsFTPd ([\w.]+)", "ftp", "vsFTPd {0}"),
    (r"220[- ].*?ProFTPD ([\w.]+)", "ftp", "ProFTPD {0}"),
    (r"220[- ].*?Pure-FTPd", "ftp", "Pure-FTPd"),
    (r"220[- ].*?FileZilla", "ftp", "FileZilla Server"),
    (r"Server:\s*nginx/?([\d.]+)?", "http", "nginx {0}"),
    (r"Server:\s*Apache/?([\d.]+)?", "http", "Apache {0}"),
    (r"Server:\s*Microsoft-IIS/?([\d.]+)?", "http", "IIS {0}"),
    (r"Server:\s*lighttpd/?([\d.]+)?", "http", "lighttpd {0}"),
    (r"Server:\s*openresty/?([\d.]+)?", "http", "OpenResty {0}"),
    (r"Server:\s*cloudflare", "http", "Cloudflare"),
    (r"Server:\s*Google Frontend", "http", "Google Frontend"),
    (r"X-Powered-By:\s*([^\r\n]+)", "http", "{0}"),
    (r"HTTP/\d\.\d\s+(\d{3})", "http", "HTTP {0}"),
    (r"MySQL|MariaDB", "mysql", "MySQL/MariaDB"),
    (r"redis_version:([\w.]+)", "redis", "Redis {0}"),
    (r"-ERR.*?Redis", "redis", "Redis"),
    (r"RFB\s+([\d.]+)", "vnc", "VNC protocol {0}"),
    (r"AMQP", "amqp", "AMQP"),
    (r"^\+PONG", "irc", "IRC"),
]

_PROBE_PAYLOADS: dict[int, bytes] = {
    port: (b"HEAD / HTTP/1.0\r\nHost: kmax.local\r\nUser-Agent: kmax/1.0\r\n"
           b"Accept: */*\r\nConnection: close\r\n\r\n")
    for port in sorted(set(WEB_PORTS) | {80, 8080, 8000, 8081, 8888, 9000, 5000})
}


def fingerprint(banner: str, port: int) -> tuple[str, str]:
    """Infer ``(service, version)`` from a banner; falls back to the port table."""
    text = " ".join(banner.replace("\r", " ").replace("\n", " ").split())
    for pattern, service, template in _BANNER_RULES:
        match = re.search(pattern, text, re.I)
        if not match:
            continue
        groups = ["" if group is None else group for group in match.groups()]
        version = template
        for index, value in enumerate(groups):
            version = version.replace("{" + str(index) + "}", value)
        return service, " ".join(version.split()).strip()
    return service_for(port), ""


def _clean_banner(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    text = "".join(ch if (ch.isprintable() or ch == "\t") else "." for ch in text)
    return " ".join(text.split())[:220]


# --------------------------------------------------------------------------- #
# Probes
# --------------------------------------------------------------------------- #
async def _connect(host: str, port: int, timeout: float):
    return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)


async def grab_banner(host: str, port: int, timeout: float, tls: bool = False) -> str:
    """Open a socket, coax the service into talking and return a clean banner."""
    writer = None
    try:
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context), timeout=timeout * 2.5
            )
        else:
            reader, writer = await _connect(host, port, timeout * 2)

        payload = _PROBE_PAYLOADS.get(port)
        if payload:
            writer.write(payload)
            await writer.drain()

        chunks: list[bytes] = []
        deadline = time.perf_counter() + max(0.3, timeout * 1.5)
        while time.perf_counter() < deadline:
            try:
                data = await asyncio.wait_for(
                    reader.read(512), timeout=max(0.15, deadline - time.perf_counter())
                )
            except (asyncio.TimeoutError, ssl.SSLError, OSError):
                break
            if not data:
                break
            chunks.append(data)
            joined = b"".join(chunks)
            if len(joined) >= 1024 or b"\r\n\r\n" in joined:
                break

        raw = b"".join(chunks)
        if tls and not raw:
            return "tls-handshake-ok"
        return _clean_banner(raw)
    except Exception:
        return ""
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def _scan_one(host: str, port: int, opts: PortOptions,
                    semaphore: asyncio.Semaphore) -> PortResult | None:
    async with semaphore:
        latency = 0.0
        attempt = 0
        while True:
            start = time.perf_counter()
            try:
                _reader, writer = await _connect(host, port, opts.timeout)
                latency = (time.perf_counter() - start) * 1000
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                break
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                attempt += 1
                if attempt > opts.retries:
                    return None

        banner = ""
        if opts.banners:
            banner = await grab_banner(host, port, opts.timeout, tls=port in TLS_PORTS)

        if opts.service_detect and banner:
            service, version = fingerprint(banner, port)
        else:
            service, version = service_for(port), ""

        return PortResult(port=port, state="open", service=service, banner=banner,
                          version=version, latency_ms=round(latency, 2))


async def _udp_probe(host: str, port: int, timeout: float) -> bool:
    """True when a UDP response came back (i.e. the service is responsive)."""
    payloads = {
        53: (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x07version\x04bind\x00\x00\x10\x00\x03"),
        123: b"\x1b" + b"\x00" * 47,
        161: (b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00"
              b"\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),
        1900: (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'),
    }
    data = payloads.get(port, b"\x00")
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_sendto(sock, data, (host, port))
        try:
            reply = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=timeout * 2)
            return bool(reply)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def execute(opts: PortOptions, host_ip: str | None = None) -> PortScanResult:
    """Run the scan and return a fully analysed :class:`PortScanResult`."""
    address = host_ip or opts.host
    started = time.perf_counter()

    result = _execute_udp(opts, address) if opts.udp else _execute_tcp(opts, address)

    result.elapsed_s = round(time.perf_counter() - started, 3)
    result.findings = analyse(result)
    return result


def _execute_tcp(opts: PortOptions, address: str) -> PortScanResult:
    async def runner() -> list[PortResult]:
        semaphore = asyncio.Semaphore(max(1, opts.concurrency))
        progress = ui.Progress(len(opts.ports), "ports")
        tasks = [asyncio.create_task(_scan_one(opts.host, port, opts, semaphore))
                 for port in opts.ports]
        found: list[PortResult] = []
        for task in asyncio.as_completed(tasks):
            outcome = await task
            progress.tick()
            if outcome:
                found.append(outcome)
        progress.close()
        return found

    opened = sorted(asyncio.run(runner()), key=lambda item: item.port)
    return PortScanResult(host=opts.host, address=address, ports=opened,
                          probed=len(opts.ports), method="tcp-connect")


def _execute_udp(opts: PortOptions, address: str) -> PortScanResult:
    async def runner() -> list[PortResult]:
        semaphore = asyncio.Semaphore(max(1, opts.concurrency))
        progress = ui.Progress(len(opts.ports), "udp")

        async def one(port: int) -> PortResult | None:
            async with semaphore:
                responsive = await _udp_probe(opts.host, port, opts.timeout)
                progress.tick()
                if responsive:
                    return PortResult(port=port, state="open",
                                      service=service_for(port, "udp"),
                                      protocol="udp")
                return None

        found = [item for item in await asyncio.gather(*(one(p) for p in opts.ports)) if item]
        progress.close()
        return found

    ui.warn("UDP is best-effort: 'open' means a response arrived, silence is ambiguous")
    opened = sorted(asyncio.run(runner()), key=lambda item: item.port)
    return PortScanResult(host=opts.host, address=address, ports=opened,
                          probed=len(opts.ports), method="udp-probe")


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    21: ("high", "FTP sends credentials in clear text", "Disable FTP; use SFTP or FTPS."),
    23: ("critical", "Telnet transmits everything in clear text",
         "Disable telnet immediately; use SSH with keys."),
    25: ("low", "SMTP reachable; open-relay risk",
         "Require authentication and STARTTLS; disable relaying."),
    69: ("medium", "TFTP has no authentication", "Disable unless required for netboot."),
    111: ("medium", "rpcbind advertises internal RPC services",
          "Filter 111/udp at the perimeter."),
    135: ("high", "MSRPC endpoint mapper exposed", "Block 135/tcp at the perimeter."),
    137: ("high", "NetBIOS name service exposed", "Disable NetBIOS over TCP/IP."),
    139: ("high", "NetBIOS session service exposed", "Disable NetBIOS over TCP/IP."),
    445: ("critical", "SMB exposed - ransomware and relay attacks",
          "Block 445 at the perimeter, patch, and enforce SMB signing."),
    512: ("high", "rexec service exposed", "Disable legacy r-services."),
    513: ("high", "rlogin service exposed", "Disable legacy r-services."),
    514: ("high", "rsh/syslog service exposed", "Disable legacy r-services."),
    873: ("medium", "rsync exposed, often anonymous", "Require auth and restrict source IPs."),
    1433: ("high", "MSSQL reachable", "Restrict to the app tier and audit the 'sa' account."),
    1521: ("high", "Oracle listener reachable", "Restrict to the app tier."),
    2049: ("high", "NFS exported", "Bind to a trusted network; avoid no_root_squash."),
    2375: ("critical", "Unauthenticated Docker API exposed",
           "Never publish 2375; enable TLS on 2376 with client certificates."),
    3306: ("high", "MySQL reachable", "Bind to localhost or the app tier; no remote root."),
    3389: ("high", "RDP exposed", "Put RDP behind a VPN and enable NLA."),
    5432: ("high", "PostgreSQL reachable", "Restrict via pg_hba.conf and the firewall."),
    5900: ("high", "VNC exposed", "Tunnel over SSH/VPN and set a strong password."),
    5984: ("high", "CouchDB reachable (Fauxton admin)", "Require auth and bind locally."),
    6379: ("critical", "Redis reachable - unauthenticated RCE in many builds",
           "Bind to localhost, enable requirepass, use ACLs."),
    6443: ("medium", "Kubernetes API server exposed", "Restrict to control-plane networks."),
    9200: ("high", "Elasticsearch reachable", "Enable security and bind internally."),
    11211: ("high", "memcached reachable - amplification risk",
            "Bind locally and firewall UDP."),
    27017: ("critical", "MongoDB reachable - historic unauthenticated data leak",
            "Enable auth, bind locally, firewall 27017."),
    4444: ("high", "Port 4444 open (common reverse-shell port)",
           "Confirm the service is legitimate."),
    31337: ("high", "Port 31337 open (common backdoor port)",
            "Confirm the service is legitimate."),
    61616: ("high", "ActiveMQ broker exposed", "Require auth; restrict network access."),
    15672: ("medium", "RabbitMQ management UI exposed",
            "Restrict access and change the default credentials."),
    2181: ("medium", "ZooKeeper reachable", "Bind to trusted hosts only."),
    50000: ("medium", "SAP DB2 listener exposed", "Restrict to the app tier."),
}


def analyse(result: PortScanResult) -> list[Finding]:
    """Build severity-tagged findings from an open-port set."""
    findings: list[Finding] = []
    open_ports = {item.port for item in result.ports}

    for item in result.ports:
        risk = RISKY_PORTS.get(item.port)
        if risk:
            severity, detail, remediation = risk
            label = item.service if item.service != "unknown" else f"port {item.port}"
            findings.append(Finding(
                title=f"{label} exposed on {item.port}/{item.protocol}",
                severity=severity, detail=detail, remediation=remediation,
                source="portscan",
            ))
        elif item.banner and "Server:" in item.banner and item.port not in TLS_PORTS:
            findings.append(Finding(
                title=f"HTTP service answering on port {item.port}",
                severity="medium",
                detail=f"Banner: {item.banner[:120]}",
                remediation="Serve over TLS and redirect plain HTTP with HSTS.",
                source="portscan",
            ))

    if open_ports & set(TLS_PORTS) and 80 in open_ports:
        findings.append(Finding(
            title="Plain HTTP and HTTPS both exposed",
            severity="low",
            detail="A TLS port is open but port 80 answers as well.",
            remediation="Redirect all HTTP traffic to HTTPS and send HSTS.",
            source="portscan",
        ))

    if result.probed and len(open_ports) == result.probed and result.probed > 20:
        findings.append(Finding(
            title="Every probed port answered",
            severity="medium",
            detail="A host answering on 100% of probed ports is usually a captive "
                   "portal, an IDS/IPS or a tarpit rather than a real service.",
            remediation="Re-scan from another network segment to confirm.",
            source="portscan",
        ))

    if not result.ports:
        findings.append(Finding(
            title="No open ports found",
            severity="good",
            detail=f"All {result.probed} probed ports were closed or filtered.",
            source="portscan",
        ))
    elif 22 in open_ports and 23 not in open_ports:
        findings.append(Finding(
            title="SSH available, telnet closed",
            severity="good",
            detail="Remote administration appears to travel over SSH.",
            source="portscan",
        ))

    if is_private(result.address):
        findings.append(Finding(
            title="Target is on a private network",
            severity="info",
            detail=f"{result.address} is RFC1918 space, so this is an internal test.",
            source="portscan",
        ))
    return findings


def summarise(result: PortScanResult) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in result.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render(result: PortScanResult, report=None) -> None:
    ui.section(f"Port scan - {result.host}", "\u25c6")
    ui.kv([
        ("Address", result.address or result.host),
        ("Method", f"{result.method} (no raw sockets needed)"),
        ("Probed", result.probed),
        ("Open", len(result.ports)),
        ("Duration", f"{result.elapsed_s:.2f}s"),
    ])

    if result.ports:
        ui.section("Open ports", "\u25c8")
        ui.table(
            ["Port", "Proto", "Service", "Version", "Latency", "Banner"],
            [[item.port, item.protocol, item.service, item.version or "-",
              f"{item.latency_ms:.0f}ms", (item.banner or "-")[:72]]
             for item in result.ports],
            limit=90,
        )
        ui.plain(ui.c("  (latency is a single-probe measurement, not an SLA)", "gray"))
    elif not ui.is_quiet():
        ui.warn("no open ports in the probed set")

    if result.findings:
        ui.section("Exposure analysis", "\u2691")
        for finding in result.findings:
            ui.plain(f"  {ui.severity_tag(finding.severity)} {finding.title}")
            if finding.detail:
                ui.plain(f"        {ui.c(finding.detail, 'gray')}")

    if report is not None:
        report.kv(f"Port scan - {result.host}", [
            ("Address", result.address or result.host),
            ("Method", result.method),
            ("Probed", result.probed),
            ("Open", len(result.ports)),
            ("Duration", f"{result.elapsed_s:.2f}s"),
        ])
        report.table("Open ports",
                     ["Port", "Proto", "Service", "Version", "Latency (ms)", "Banner"],
                     [[item.port, item.protocol, item.service, item.version or "",
                       f"{item.latency_ms:.1f}", item.banner] for item in result.ports])
        report.findings(result.findings, "Exposure analysis")
        report.note("open_ports", [item.port for item in result.ports])


def hosts_only(hosts: Iterable[str]) -> Sequence[str]:
    """Kept for symmetry with the sweep module."""
    return list(hosts)
