"""Host discovery: ICMP echo, TCP probes, the ARP cache and optional ``nmap -sn``.

The built-in sweep needs no privileges at all: it shells out to ``ping`` and
opens ordinary TCP connections, which is exactly what you want on a Kali box
where ``kmax`` may run as an ordinary user. When ``nmap`` is installed the
``--nmap`` flag delegates discovery to it and normalises the output back into
the same :class:`HostResult` objects.
"""

from __future__ import annotations

import asyncio
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from ..core import ui
from ..core.models import Finding, HostResult
from ..core.utils import (
    TargetError,
    have,
    is_private,
    parse_cidr,
    read_text,
    resolve,
    reverse_dns,
    run,
)

__all__ = ["SweepOptions", "SweepResult", "execute", "render", "arp_table",
           "vendor_for", "ping_once", "OUI_VENDORS", "DEFAULT_TCP_PROBES"]

DEFAULT_TCP_PROBES: tuple[int, ...] = (80, 443, 22, 445, 3389, 8080)

# A compact OUI table covering the vendors most often seen on lab/enterprise LANs.
OUI_VENDORS: dict[str, str] = {
    "000c29": "VMware", "005056": "VMware", "000569": "VMware",
    "080027": "Oracle VirtualBox", "0a0027": "Oracle VirtualBox",
    "525400": "QEMU/KVM", "00155d": "Microsoft Hyper-V",
    "000d3a": "Microsoft", "001c42": "Parallels",
    "b827eb": "Raspberry Pi Foundation", "dca632": "Raspberry Pi Trading",
    "e45f01": "Raspberry Pi Trading", "2ccf67": "Raspberry Pi Trading",
    "00163e": "Xensource", "001c14": "VMware",
    "00005e": "IANA",
    "3c5a37": "Samsung", "f4f5d8": "Samsung", "8c7712": "Samsung",
    "001a11": "Google", "3c5ab4": "Google", "f4f5e8": "Google",
    "f0189800": "Apple", "001451": "Apple", "3c0754": "Apple",
    "a4c361": "Apple", "f0766f": "Apple", "ac87a3": "Apple",
    "0017c8": "KYOCERA", "00248c": "ASUSTek", "1c872c": "ASUSTek",
    "e03f49": "ASUSTek", "2c56dc": "ASUSTek", "04d9f5": "ASUSTek",
    "001e58": "D-Link", "1cbdb9": "D-Link", "00265a": "D-Link",
    "0024b2": "Netgear", "204e7f": "Netgear", "b03956": "Netgear",
    "9c3dcf": "Netgear", "0009bf": "Cisco-Linksys", "0018f8": "Cisco-Linksys",
    "0023eb": "Cisco", "f02929": "Cisco", "0025b4": "Cisco",
    "000c85": "Cisco", "d4a02a": "Cisco", "0026cb": "Cisco",
    "00e04c": "Realtek", "001cc4": "HP", "002481": "HP",
    "3c4a92": "HP", "9457a5": "HP", "d8d385": "HP", "6cc217": "HP",
    "3464a9": "HP", "1c98ec": "HP", "a45d36": "HP",
    "0026b9": "Dell", "b8ca3a": "Dell", "f8bc12": "Dell",
    "18a99b": "Dell", "001c23": "Dell", "002219": "Dell", "5c260a": "Dell",
    "0019d2": "Intel", "3c9509": "Intel", "a0a8cd": "Intel",
    "8c1645": "Intel", "e4a471": "Intel", "00aa00": "Intel",
    "000e0c": "Intel", "001b21": "Intel", "001e67": "Intel",
    "00125a": "Microsoft", "0017fa": "Microsoft", "001dd8": "Microsoft",
    "0050f2": "Microsoft", "7c1e52": "Microsoft", "281878": "Microsoft",
    "0014ee": "Western Digital", "002590": "Super Micro", "003048": "Super Micro",
    "0c9d92": "ASUS", "08606e": "ASUS", "704d7b": "ASUS",
    "b06ebf": "ASUS", "20cf30": "ASUS", "d850e6": "ASUS",
    "e8de27": "TP-Link", "50c7bf": "TP-Link", "a42bb0": "TP-Link",
    "001d0f": "TP-Link", "c46e1f": "TP-Link", "f4f26d": "TP-Link",
    "fcaa14": "GIGA-BYTE", "1c1b0d": "GIGA-BYTE", "b42e99": "GIGA-BYTE",
    "001596": "GIGA-BYTE", "74d435": "GIGA-BYTE",
    "0050ba": "D-Link", "001b11": "D-Link",
}


@dataclass
class SweepOptions:
    targets: list[str]
    timeout: float = 1.0
    workers: int = 128
    ping: bool = True
    tcp_ports: tuple[int, ...] = DEFAULT_TCP_PROBES
    use_nmap: bool = False
    resolve_names: bool = True


@dataclass
class SweepResult:
    targets: list[str]
    hosts: list[HostResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    elapsed_s: float = 0.0
    scanned: int = 0
    method: str = "icmp+tcp"

    @property
    def alive(self) -> list[HostResult]:
        return list(self.hosts)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def vendor_for(mac: str) -> str:
    """Look a MAC address up in the bundled OUI table."""
    if not mac:
        return ""
    key = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    for size in (9, 6):
        prefix = key[:size]
        if prefix in OUI_VENDORS:
            return OUI_VENDORS[prefix]
    return ""


def arp_table() -> dict[str, tuple[str, str]]:
    """``{ip: (mac, iface)}`` from ``/proc/net/arp`` or the ``arp`` command."""
    table: dict[str, tuple[str, str]] = {}
    raw = read_text("/proc/net/arp")
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[3] != "00:00:00:00:00:00":
            table[parts[0]] = (parts[3], parts[5])
    if not table and have("arp"):
        code, out, _ = run(["arp", "-an"], timeout=8)
        if code == 0:
            for ip, mac in re.findall(
                r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})", out
            ):
                table[ip] = (mac, "")
    return table


def ping_once(host: str, timeout: float = 1.0) -> tuple[bool, float]:
    """ICMP echo via the system ``ping`` binary; returns ``(alive, rtt_ms)``."""
    if not have("ping"):
        return False, 0.0
    wait = max(1, int(round(timeout)))
    start = time.perf_counter()
    code, out, _ = run(["ping", "-c", "1", "-n", "-W", str(wait), host], timeout=wait + 3)
    elapsed = (time.perf_counter() - start) * 1000
    if code == 0:
        match = re.search(r"time=([\d.]+)", out)
        if match:
            elapsed = float(match.group(1))
        return True, round(elapsed, 2)
    return False, 0.0


async def tcp_probe(host: str, port: int, timeout: float) -> tuple[bool, float]:
    start = time.perf_counter()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        elapsed = (time.perf_counter() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, round(elapsed, 2)
    except Exception:
        return False, 0.0


async def _probe(host: str, opts: SweepOptions,
                 semaphore: asyncio.Semaphore) -> HostResult | None:
    async with semaphore:
        if opts.ping:
            alive, latency = await asyncio.to_thread(ping_once, host, opts.timeout)
            if alive:
                return HostResult(address=host, state="up", latency_ms=latency,
                                  method="icmp-echo")
        for port in opts.tcp_ports:
            alive, latency = await tcp_probe(host, port, opts.timeout)
            if alive:
                return HostResult(address=host, state="up", latency_ms=latency,
                                  method=f"tcp/{port}")
    return None


# --------------------------------------------------------------------------- #
# nmap wrapper
# --------------------------------------------------------------------------- #
def nmap_sweep(target: str, timeout: float = 240.0) -> list[HostResult]:
    """Run ``nmap -sn`` and parse the greppable output."""
    if not have("nmap"):
        ui.warn("nmap not found - using the built-in scanner instead")
        return []
    cmd = ["nmap", "-sn", "-PE", "-PS80,443,22", "-T4", "--max-retries", "1",
           "--host-timeout", "30s", "-oG", "-", target]
    ui.debug("running: " + " ".join(cmd))
    code, out, err = run(cmd, timeout=timeout)
    if code != 0:
        ui.warn(f"nmap exited with {code}: {err.strip()[:160]}")
        return []
    hosts: list[HostResult] = []
    for line in out.splitlines():
        if not line.startswith("Host:") or "Status: Up" not in line:
            continue
        found = re.search(r"Host:\s+(\S+)", line)
        if not found:
            continue
        latency = re.search(r"Latency:\s+([\d.]+)s", line)
        hosts.append(HostResult(
            address=found.group(1), state="up",
            latency_ms=round(float(latency.group(1)) * 1000, 2) if latency else 0.0,
            method="nmap -sn",
        ))
    return hosts


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def execute(opts: SweepOptions) -> SweepResult:
    """Discover live hosts across ``opts.targets`` (IPs and/or CIDRs)."""
    addresses: list[str] = []
    for entry in opts.targets:
        text = entry.strip()
        if not text:
            continue
        if "/" in text:
            addresses.extend(parse_cidr(text))
        else:
            addresses.append(text)
    addresses = list(dict.fromkeys(addresses))
    if not addresses:
        raise TargetError("no usable targets after expansion")

    started = time.perf_counter()
    ui.info(f"probing {len(addresses)} address(es) with {opts.workers} workers "
            f"and a {opts.timeout:.1f}s timeout")

    hosts: list[HostResult] = []
    method = "icmp+tcp"

    if opts.use_nmap:
        method = "nmap -sn"
        for entry in opts.targets:
            target = entry if "/" in entry else f"{entry}/32"
            hosts.extend(nmap_sweep(target))

    if not hosts:
        async def runner() -> list[HostResult]:
            semaphore = asyncio.Semaphore(max(1, opts.workers))
            progress = ui.Progress(len(addresses), "sweeping")
            tasks = [asyncio.create_task(_probe(address, opts, semaphore))
                     for address in addresses]
            found: list[HostResult] = []
            for task in asyncio.as_completed(tasks):
                outcome = await task
                progress.tick()
                if outcome:
                    found.append(outcome)
            progress.close()
            return found

        hosts = asyncio.run(runner())
        if opts.use_nmap:
            method = "nmap -sn + built-in"

    by_address = {host.address: host for host in hosts}

    # Anything in the ARP cache is definitively alive on the local segment.
    arp = arp_table()
    requested = set(addresses)
    for ip, (mac, _iface) in arp.items():
        if ip not in requested:
            continue
        host = by_address.get(ip)
        if host is None:
            host = HostResult(address=ip, state="up", method="arp-cache")
            by_address[ip] = host
            hosts.append(host)
        host.mac = mac
        host.vendor = vendor_for(mac)

    if opts.resolve_names:
        for host in hosts:
            if host.hostname:
                continue
            name = reverse_dns(host.address, timeout=min(2.0, opts.timeout + 1))
            if name and not name.startswith(host.address):
                host.hostname = name

    hosts.sort(key=lambda item: tuple(int(p) for p in item.address.split("."))
               if re.fullmatch(r"\d+(\.\d+){3}", item.address) else (999, 999, 999, 999))

    result = SweepResult(targets=opts.targets, hosts=hosts, method=method,
                         scanned=len(addresses))
    result.elapsed_s = round(time.perf_counter() - started, 3)
    result.findings = analyse(result)
    return result


def analyse(result: SweepResult) -> list[Finding]:
    findings: list[Finding] = []
    if not result.hosts:
        findings.append(Finding(
            title="No live hosts discovered",
            severity="info",
            detail="ICMP may be filtered and the TCP probe ports may all be closed. "
                   "Try --tcp 1,7,9,13,21,22,23,25,80,443,3389 or -Pn-style sweeping.",
            remediation="Confirm the network range, gateway and VLAN.",
            source="netscan",
        ))
        return findings

    findings.append(Finding(
        title=f"{len(result.hosts)} live host(s) discovered",
        severity="info",
        detail=f"Sweep covered {result.scanned} address(es) via {result.method}.",
        source="netscan",
    ))

    unknown_vendors = [host for host in result.hosts if host.mac and not host.vendor]
    if unknown_vendors:
        findings.append(Finding(
            title=f"{len(unknown_vendors)} device(s) with unclassified MAC vendor",
            severity="low",
            detail="Unrecognised OUIs often indicate embedded devices, IoT or VMs.",
            remediation="Inventory these devices and confirm they are authorised.",
            source="netscan",
        ))

    if result.hosts and len(result.hosts) == result.scanned and result.scanned > 10:
        findings.append(Finding(
            title="Every address answered",
            severity="medium",
            detail="A full sweep response points at a tarpit, honeypot or a proxy ARP.",
            remediation="Verify from a different segment.",
            source="netscan",
        ))
    return findings


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render(result: SweepResult, report=None) -> None:
    ui.section("Host discovery", "\u25c6")
    ui.kv([
        ("Targets", ", ".join(result.targets)),
        ("Addresses probed", result.scanned),
        ("Live hosts", len(result.hosts)),
        ("Method", result.method),
        ("Duration", f"{result.elapsed_s:.2f}s"),
    ])

    if result.hosts:
        ui.section("Live hosts", "\u25c8")
        ui.table(["Address", "Hostname", "State", "MAC", "Vendor", "Latency", "Method"],
                 [host.to_row() for host in result.hosts], limit=60)
    elif not ui.is_quiet():
        ui.warn("no live hosts found (ICMP may be filtered; try --tcp with more ports)")

    if result.findings:
        ui.section("Discovery notes", "\u2691")
        for finding in result.findings:
            ui.plain(f"  {ui.severity_tag(finding.severity)} {finding.title}")
            if finding.detail:
                ui.plain(f"        {ui.c(finding.detail, 'gray')}")

    if report is not None:
        report.kv("Host discovery", [
            ("Targets", ", ".join(result.targets)),
            ("Addresses probed", result.scanned),
            ("Live hosts", len(result.hosts)),
            ("Method", result.method),
            ("Duration", f"{result.elapsed_s:.2f}s"),
        ])
        report.table("Live hosts",
                     ["Address", "Hostname", "State", "MAC", "Vendor", "Latency (ms)",
                      "Method"],
                     [[host.address, host.hostname, host.state, host.mac, host.vendor,
                       f"{host.latency_ms:.1f}" if host.latency_ms else "-", host.method]
                      for host in result.hosts])
        report.findings(result.findings, "Discovery notes")
        report.note("live_hosts", [host.address for host in result.hosts])


def resolve_targets(targets: Iterable[str]) -> list[str]:
    """Resolve hostnames inside a target list to IP literals."""
    resolved: list[str] = []
    for item in targets:
        if re.fullmatch(r"\d+(\.\d+){3}(/\d+)?", item):
            resolved.append(item)
            continue
        address = resolve(item)
        resolved.append(address or item)
    return resolved


def is_local_target(address: str) -> bool:
    return is_private(address) or address.startswith("127.")


def sockaddr_host(host: str) -> str:
    """Best-effort numeric form of a host string (used by callers/tests)."""
    try:
        return socket.gethostbyname(host)
    except OSError:
        return host


def default_prefix_targets(prefix: str = "24") -> Sequence[str]:
    """Convenience helper returning the CIDR string for the local network."""
    from ..core.utils import guess_network, local_addresses

    for _iface, cidr in local_addresses().items():
        network = guess_network(cidr.split("/")[0], int(prefix))
        if network:
            return [network]
    return []
