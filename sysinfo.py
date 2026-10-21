"""Local system intelligence: OS, kernel, hardware, disks, interfaces, posture.

Everything here reads from ``/proc``, ``/sys``, ``/etc`` or a small, fixed set of
coreutils commands, and degrades gracefully on unusual systems: a missing file
becomes an ``"-"`` in the report instead of a crash.
"""

from __future__ import annotations

import getpass
import ipaddress
import os
import platform
import re
import shutil
import socket
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..core import ui
from ..core.models import Finding, SysInfo
from ..core.utils import (
    have,
    human_bytes,
    human_time,
    is_root,
    read_text,
    run,
)

__all__ = [
    "SysOptions", "SysResult", "execute", "render", "gather", "analyse",
    "os_release", "cpu_info", "memory_info", "disk_info", "interfaces",
    "default_gateway", "dns_servers", "public_ip", "tool_inventory",
]

_RUNTIME_COMMANDS = ("python3", "python", "node", "npm", "go", "rustc", "java",
                     "php", "ruby", "perl", "gcc", "git", "docker", "kubectl")

_SECURITY_COMMANDS = (
    "nmap", "dig", "whois", "curl", "wget", "openssl", "tcpdump", "tshark",
    "aircrack-ng", "hydra", "sqlmap", "john", "hashcat", "nikto", "gobuster",
    "ffuf", "wpscan", "masscan", "netcat", "nc", "socat", "metasploit",
    "msfconsole", "burpsuite", "wireshark", "ettercap", "responder",
    "impacket", "crackmapexec", "enum4linux", "smbclient", "rdesktop",
    "xfreerdp", "searchsploit", "setoolkit", "beef", "mitmproxy",
)


@dataclass
class SysOptions:
    include_public_ip: bool = False
    include_tools: bool = True
    include_packages: bool = True
    timeout: float = 6.0


@dataclass
class SysResult:
    info: SysInfo
    findings: list[Finding]
    elapsed_s: float = 0.0


# --------------------------------------------------------------------------- #
# Gatherers
# --------------------------------------------------------------------------- #
def os_release() -> dict[str, str]:
    """Parse ``/etc/os-release`` into a dict."""
    data: dict[str, str] = {}
    for line in read_text("/etc/os-release").splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def os_name() -> str:
    release = os_release()
    return release.get("PRETTY_NAME") or release.get("NAME") or platform.system() or "-"


def boot_time() -> tuple[float, str]:
    """Return ``(epoch_seconds, iso_local_string)`` for the last boot."""
    raw = read_text("/proc/stat")
    match = re.search(r"^btime\s+(\d+)", raw, re.M)
    if not match:
        return 0.0, ""
    epoch = float(match.group(1))
    stamp = datetime.fromtimestamp(epoch).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    return epoch, stamp


def uptime_seconds() -> float:
    parts = read_text("/proc/uptime").split()
    if not parts:
        return 0.0
    try:
        return float(parts[0])
    except ValueError:
        return 0.0


def cpu_info() -> dict[str, Any]:
    raw = read_text("/proc/cpuinfo")
    models = re.findall(r"^(?:model name|cpu model|Hardware)\s*:\s*(.+)$", raw, re.M)
    cores = len(re.findall(r"^processor\s*:", raw, re.M))
    speeds = re.findall(r"^cpu MHz\s*:\s*([\d.]+)$", raw, re.M)
    flags = ""
    match = re.search(r"^flags\s*:\s*(.+)$", raw, re.M)
    if match:
        flags = match.group(1)
    return {
        "model": (models[0].strip() if models else platform.processor() or "unknown"),
        "cores": cores or (os.cpu_count() or 0),
        "mhz": max((float(value) for value in speeds), default=0.0),
        "flags": flags.split() if flags else [],
    }


def load_average() -> tuple[float, float, float]:
    try:
        return os.getloadavg()
    except (OSError, AttributeError):
        return (0.0, 0.0, 0.0)


def memory_info() -> dict[str, float]:
    info: dict[str, float] = {}
    for line in read_text("/proc/meminfo").splitlines():
        key, _, rest = line.partition(":")
        fields = rest.strip().split()
        if fields and fields[0].isdigit():
            info[key.strip()] = float(fields[0]) * 1024
    total = info.get("MemTotal", 0.0)
    available = info.get("MemAvailable", info.get("MemFree", 0.0))
    cached = info.get("Cached", 0.0)
    buffers = info.get("Buffers", 0.0)
    swap_total = info.get("SwapTotal", 0.0)
    swap_free = info.get("SwapFree", 0.0)
    used = max(0.0, total - available)
    return {
        "total": total,
        "used": used,
        "available": available,
        "cached": cached + buffers,
        "percent": (used / total * 100) if total else 0.0,
        "swap_total": swap_total,
        "swap_used": max(0.0, swap_total - swap_free),
    }


def disk_info() -> list[dict[str, Any]]:
    """Mounted filesystems with size/used/free, from ``df`` plus the root usage."""
    rows: list[dict[str, Any]] = []
    seen_mounts: set[str] = set()

    if have("df"):
        code, out, _ = run(
            ["df", "-B1", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs",
             "-x", "overlay", "-x", "ramfs"],
            timeout=12,
        )
        if code == 0:
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 6:
                    continue
                if not parts[1].isdigit():
                    continue
                mount = parts[5]
                if mount in seen_mounts:
                    continue
                seen_mounts.add(mount)
                size, used, free = int(parts[1]), int(parts[2]), int(parts[3])
                rows.append({
                    "filesystem": parts[0], "mount": mount, "size": size,
                    "used": used, "free": free,
                    "percent": (used / size * 100) if size else 0.0,
                })

    if not rows:
        try:
            usage = shutil.disk_usage("/")
            rows.append({
                "filesystem": "-", "mount": "/", "size": usage.total,
                "used": usage.used, "free": usage.free,
                "percent": usage.used / usage.total * 100 if usage.total else 0.0,
            })
        except OSError:
            pass
    return rows


def interfaces() -> list[dict[str, Any]]:
    """Network interfaces from ``/sys/class/net`` enriched with ``ip addr``."""
    base = "/sys/class/net"
    rows: list[dict[str, Any]] = []
    if os.path.isdir(base):
        for name in sorted(os.listdir(base)):
            if name == "lo":
                continue
            path = os.path.join(base, name)
            row: dict[str, Any] = {
                "name": name,
                "state": read_text(os.path.join(path, "operstate")).strip() or "unknown",
                "mac": read_text(os.path.join(path, "address")).strip(),
                "mtu": read_text(os.path.join(path, "mtu")).strip(),
                "ipv4": "",
                "ipv6": "",
                "speed": "",
            }
            speed = read_text(os.path.join(path, "speed")).strip()
            if speed.lstrip("-").isdigit() and int(speed) > 0:
                row["speed"] = f"{int(speed)} Mb/s"
            elif os.path.isdir(os.path.join(path, "wireless")):
                row["speed"] = "wireless"
            rows.append(row)

    if have("ip"):
        code, out, _ = run(["ip", "-o", "addr", "show"], timeout=10)
        if code == 0:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                iface, family, cidr = parts[1], parts[2], parts[3]
                for row in rows:
                    if row["name"] != iface:
                        continue
                    if family == "inet" and not row["ipv4"]:
                        row["ipv4"] = cidr
                    elif family == "inet6" and not row["ipv6"]:
                        address = cidr.split("/")[0]
                        if not address.lower().startswith("fe80"):
                            row["ipv6"] = cidr
    return rows


def default_gateway() -> str:
    if have("ip"):
        code, out, _ = run(["ip", "route", "show", "default"], timeout=8)
        if code == 0 and out.strip():
            parts = out.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    for line in read_text("/proc/net/route").splitlines()[1:]:
        fields = line.split()
        if len(fields) > 2 and fields[1] == "00000000":
            raw = fields[2]
            return ".".join(str(int(raw[i:i + 2], 16)) for i in (6, 4, 2, 0))
    return ""


def dns_servers() -> list[str]:
    servers: list[str] = []
    for line in read_text("/etc/resolv.conf").splitlines():
        stripped = line.strip()
        if stripped.startswith("nameserver"):
            parts = stripped.split()
            if len(parts) > 1 and parts[1] not in servers:
                servers.append(parts[1])
    return servers


def public_ip(timeout: float = 5.0) -> str:
    """Best-effort public IP; returns a reason string when there is no egress."""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip",
                "https://icanhazip.com"):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "kmax/1.0"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                value = response.read(120).decode("utf-8", "replace").strip()
                if value:
                    return value
        except Exception:
            continue
    return "unavailable (no egress or blocked)"


def package_counts() -> dict[str, str]:
    info: dict[str, str] = {"dpkg packages": "-", "apt": "-", "pip": "-",
                            "snap": "-", "flatpak": "-"}
    if have("dpkg-query"):
        code, out, _ = run(["dpkg-query", "-f", "${binary:Package}\n", "-W"], timeout=25)
        if code == 0:
            info["dpkg packages"] = str(len(out.splitlines()))
    if have("apt"):
        code, out, _ = run(["apt", "--version"], timeout=10)
        if code == 0 and out:
            info["apt"] = out.split()[1] if len(out.split()) > 1 else "installed"
    if have("pip3"):
        code, out, _ = run(["pip3", "--version"], timeout=12)
        if code == 0 and out:
            info["pip"] = out.split()[1]
    if have("snap"):
        info["snap"] = "installed"
    if have("flatpak"):
        info["flatpak"] = "installed"
    return info


def runtime_versions() -> dict[str, str]:
    versions: dict[str, str] = {"python (kmax runtime)": platform.python_version()}
    probes: dict[str, list[str]] = {
        "node": ["node", "--version"],
        "npm": ["npm", "--version"],
        "go": ["go", "version"],
        "rustc": ["rustc", "--version"],
        "java": ["java", "-version"],
        "gcc": ["gcc", "--version"],
        "git": ["git", "--version"],
        "docker": ["docker", "--version"],
        "kubectl": ["kubectl", "version", "--client", "--output=yaml"],
    }
    for name, command in probes.items():
        if not have(command[0]):
            continue
        code, out, err = run(command, timeout=8)
        text = (out or err or "").strip().splitlines()
        if code == 0 and text:
            versions[name] = text[0][:80]
    return versions


def tool_inventory() -> dict[str, str]:
    """Which Kali/security tools are installed (available/missing only)."""
    inventory: dict[str, str] = {}
    for name in _SECURITY_COMMANDS:
        inventory[name] = "available" if have(name) else "missing"
    return inventory


def hardware_summary() -> dict[str, str]:
    summary: dict[str, str] = {}
    product = read_text("/sys/class/dmi/id/product_name").strip()
    vendor = read_text("/sys/class/dmi/id/sys_vendor").strip()
    if vendor or product:
        summary["Chassis"] = " ".join(part for part in (vendor, product) if part)
    bios = read_text("/sys/class/dmi/id/bios_version").strip()
    if bios:
        summary["BIOS"] = bios
    if os.path.isdir("/sys/class/power_supply"):
        batteries = [entry for entry in os.listdir("/sys/class/power_supply")
                     if entry.startswith("BAT")]
        if batteries:
            capacity = read_text(f"/sys/class/power_supply/{batteries[0]}/capacity").strip()
            status = read_text(f"/sys/class/power_supply/{batteries[0]}/status").strip()
            if capacity:
                summary["Battery"] = f"{capacity}% ({status or 'unknown'})"
    return summary


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def gather(opts: SysOptions) -> SysInfo:
    """Collect a normalised snapshot of the local machine."""
    kernel_release = platform.release()
    epoch, boot_stamp = boot_time()
    cpu = cpu_info()
    mem = memory_info()

    release = os_release()
    info = SysInfo(
        os_name=os_name(),
        kernel=f"{kernel_release} ({platform.machine()})",
        architecture=platform.machine(),
        hostname=socket.gethostname(),
        user=_user(),
        elevated=is_root(),
        uptime=human_time(uptime_seconds() or time.time() - epoch if epoch else uptime_seconds()),
        boot_time=boot_stamp,
        cpu_model=cpu["model"],
        cpu_cores=cpu["cores"],
        cpu_mhz=round(cpu["mhz"], 1),
        mem_total=mem["total"],
        mem_used=mem["used"],
        mem_percent=round(mem["percent"], 1),
        swap_total=mem["swap_total"],
        swap_used=mem["swap_used"],
        disks=disk_info(),
        interfaces=interfaces(),
        gateway=default_gateway(),
        dns_servers=dns_servers(),
        packages=package_counts() if opts.include_packages else {},
        runtimes=runtime_versions(),
        tools=tool_inventory() if opts.include_tools else {},
    )
    if release.get("VERSION_ID"):
        info.os_name = f"{info.os_name} (build {release['VERSION_ID']})"
    if opts.include_public_ip:
        info.public_ip = public_ip(opts.timeout)
    return info


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - defensive
        return os.environ.get("USER", "unknown")


def analyse(info: SysInfo) -> list[Finding]:
    """Evaluate local hardening posture from the collected snapshot."""
    findings: list[Finding] = []

    if info.elevated:
        findings.append(Finding(
            title="Running with root privileges",
            severity="info",
            detail="Full capability is available (raw sockets, ARP, firewall reads).",
            remediation="Drop back to an unprivileged user when the scan is finished.",
            source="sysinfo",
        ))
    else:
        findings.append(Finding(
            title="Running as an unprivileged user",
            severity="good",
            detail=f"User {info.user!r}; no raw-socket features are needed by KMAX.",
            source="sysinfo",
        ))

    if info.mem_percent >= 90:
        findings.append(Finding(
            title="Memory pressure is critical",
            severity="high",
            detail=f"{info.mem_percent:.1f}% of RAM in use.",
            remediation="Close heavy processes or add RAM/swap before large scans.",
            source="sysinfo",
        ))
    elif info.mem_percent >= 75:
        findings.append(Finding(
            title="Memory usage is elevated",
            severity="medium",
            detail=f"{info.mem_percent:.1f}% of RAM in use.",
            remediation="Watch for OOM kills during concurrent scans.",
            source="sysinfo",
        ))
    else:
        findings.append(Finding(
            title="Memory usage is healthy",
            severity="good",
            detail=f"{human_bytes(info.mem_used)} of {human_bytes(info.mem_total)} used.",
            source="sysinfo",
        ))

    for disk in info.disks:
        if disk.get("percent", 0) >= 92:
            findings.append(Finding(
                title=f"Disk almost full on {disk['mount']}",
                severity="high",
                detail=f"{disk['percent']:.1f}% used "
                       f"({human_bytes(disk['free'])} free).",
                remediation="Free space: large reports and packet captures need room.",
                source="sysinfo",
            ))
        elif disk.get("percent", 0) >= 85:
            findings.append(Finding(
                title=f"Disk usage high on {disk['mount']}",
                severity="medium",
                detail=f"{disk['percent']:.1f}% used.",
                remediation="Clean package caches and old scan output.",
                source="sysinfo",
            ))

    if info.swap_total == 0:
        findings.append(Finding(
            title="No swap configured",
            severity="low",
            detail="Large concurrent scans can be killed without swap headroom.",
            remediation="Add a swapfile if the machine is memory constrained.",
            source="sysinfo",
        ))

    if not info.dns_servers:
        findings.append(Finding(
            title="No DNS resolver configured",
            severity="medium",
            detail="/etc/resolv.conf lists no nameserver.",
            remediation="Configure a resolver or pass --dns-server to the dns command.",
            source="sysinfo",
        ))

    down = [row["name"] for row in info.interfaces if row.get("state") not in ("up", "unknown")]
    if not info.interfaces:
        findings.append(Finding(
            title="No non-loopback interface found",
            severity="medium",
            detail="Network scanning will not work without an interface.",
            remediation="Bring up an interface (nmcli/wpa_supplicant).",
            source="sysinfo",
        ))
    elif down:
        findings.append(Finding(
            title=f"{len(down)} interface(s) down",
            severity="info",
            detail=", ".join(down),
            source="sysinfo",
        ))

    live_gateway = info.gateway or "-"
    findings.append(Finding(
        title=f"Default gateway: {live_gateway}",
        severity="info",
        detail=f"DNS: {', '.join(info.dns_servers) or '-'}",
        source="sysinfo",
    ))

    if info.tools:
        available = [name for name, state in info.tools.items() if state == "available"]
        missing_key = [name for name in ("nmap", "dig", "openssl")
                       if info.tools.get(name) == "missing"]
        findings.append(Finding(
            title=f"{len(available)} of {len(info.tools)} security tools on PATH",
            severity="good" if len(available) > 5 else "info",
            detail="Available: " + (", ".join(available[:18]) or "none"),
            source="sysinfo",
        ))
        if missing_key:
            findings.append(Finding(
                title=f"Key helper(s) missing: {', '.join(missing_key)}",
                severity="low",
                detail="KMAX works without them, but some checks get richer with them.",
                remediation="sudo apt install nmap dnsutils openssl",
                source="sysinfo",
            ))

    if info.public_ip and "unavailable" not in info.public_ip:
        findings.append(Finding(
            title=f"Public egress address: {info.public_ip}",
            severity="info",
            detail="Consider whether external scanning should come from a different exit.",
            source="sysinfo",
        ))

    load1, load5, load15 = load_average()
    if info.cpu_cores and load1 > info.cpu_cores * 1.5:
        findings.append(Finding(
            title="High system load",
            severity="medium",
            detail=f"Load average {load1:.2f}/{load5:.2f}/{load15:.2f} on "
                   f"{info.cpu_cores} core(s).",
            remediation="Lower --workers so the scan does not starve the box.",
            source="sysinfo",
        ))
    return findings


def execute(opts: SysOptions) -> SysResult:
    """Gather system intelligence and assess its posture."""
    started = time.perf_counter()
    info = gather(opts)
    return SysResult(info=info, findings=analyse(info),
                     elapsed_s=round(time.perf_counter() - started, 3))


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render(result: SysResult, report=None, show_tools: bool = False,
           show_packages: bool = False) -> None:
    info = result.info
    ui.section(f"System information - {info.hostname}", "\u25c6")

    ui.section("Operating system", "\u25c8")
    ui.kv([
        ("Distribution", info.os_name),
        ("Kernel", info.kernel),
        ("Architecture", info.architecture),
        ("Hostname", info.hostname),
        ("User", f"{info.user}{' (root)' if info.elevated else ''}"),
        ("Uptime", info.uptime),
        ("Booted", info.boot_time or "-"),
    ])

    ui.section("Hardware", "\u25c8")
    ui.kv([
        ("CPU", f"{info.cpu_model}"),
        ("Cores", info.cpu_cores),
        ("Max clock", f"{info.cpu_mhz:.0f} MHz" if info.cpu_mhz else "-"),
        ("Memory", f"{human_bytes(info.mem_used)} / {human_bytes(info.mem_total)} "
                   f"({info.mem_percent:.1f}%)"),
        ("Swap", f"{human_bytes(info.swap_used)} / {human_bytes(info.swap_total)}"
                 if info.swap_total else "none"),
        ("Load average", " / ".join(f"{value:.2f}" for value in load_average())),
    ])
    hardware = hardware_summary()
    if hardware:
        ui.kv([(key, value) for key, value in hardware.items()])

    if info.disks:
        ui.section("Disks", "\u25c8")
        ui.table(["Filesystem", "Mount", "Size", "Used", "Free", "Use%"],
                 [[disk.get("filesystem", "-"), disk["mount"],
                   human_bytes(disk["size"]), human_bytes(disk["used"]),
                   human_bytes(disk["free"]), f"{disk.get('percent', 0):.1f}%"]
                  for disk in info.disks],
                 aligns=["left", "left", "right", "right", "right", "right"])

    if info.interfaces:
        ui.section("Network interfaces", "\u25c8")
        ui.table(["Interface", "State", "IPv4", "IPv6", "MAC", "Speed"],
                 [[row["name"], row.get("state", "-"), row.get("ipv4") or "-",
                   (row.get("ipv6") or "-")[:28], row.get("mac") or "-",
                   row.get("speed") or "-"] for row in info.interfaces])
        ui.kv([
            ("Default gateway", info.gateway or "-"),
            ("DNS servers", ", ".join(info.dns_servers) or "-"),
        ])
    if info.public_ip:
        ui.kv([("Public IP", info.public_ip)])

    if info.runtimes:
        ui.section("Runtime versions", "\u25c8")
        ui.kv(list(info.runtimes.items()))

    if show_packages and info.packages:
        ui.section("Packages", "\u25c8")
        ui.kv(list(info.packages.items()))

    if show_tools and info.tools:
        available = {name: state for name, state in info.tools.items() if state == "available"}
        missing = [name for name, state in info.tools.items() if state == "missing"]
        ui.section("Security tool inventory", "\u25c8")
        ui.plain(f"  {ui.c('available', 'bgreen')} : "
                 + (", ".join(sorted(available)) or "none"))
        ui.plain(f"  {ui.c('missing  ', 'gray')} : " + (", ".join(missing) or "none"))

    if result.findings:
        ui.section("Posture findings", "\u2691")
        for finding in result.findings:
            ui.plain(f"  {ui.severity_tag(finding.severity)} {finding.title}")
            if finding.detail:
                ui.plain(f"        {ui.c(finding.detail, 'gray')}")

    if report is not None:
        report.kv(f"System - {info.hostname}", [
            ("Distribution", info.os_name),
            ("Kernel", info.kernel),
            ("Architecture", info.architecture),
            ("User", f"{info.user}{' (root)' if info.elevated else ''}"),
            ("Uptime", info.uptime),
            ("Booted", info.boot_time or "-"),
            ("CPU", info.cpu_model),
            ("Cores", info.cpu_cores),
            ("Memory", f"{human_bytes(info.mem_used)} / {human_bytes(info.mem_total)} "
                       f"({info.mem_percent:.1f}%)"),
            ("Swap", f"{human_bytes(info.swap_used)} / {human_bytes(info.swap_total)}"
                     if info.swap_total else "none"),
            ("Gateway", info.gateway or "-"),
            ("DNS", ", ".join(info.dns_servers) or "-"),
            ("Public IP", info.public_ip or "-"),
        ])
        if info.disks:
            report.table("Disks", ["Filesystem", "Mount", "Size", "Used", "Free", "Use%"],
                         [[disk.get("filesystem", "-"), disk["mount"], human_bytes(disk["size"]),
                           human_bytes(disk["used"]), human_bytes(disk["free"]),
                           f"{disk.get('percent', 0):.1f}%"] for disk in info.disks])
        if info.interfaces:
            report.table("Network interfaces",
                         ["Interface", "State", "IPv4", "IPv6", "MAC", "Speed"],
                         [[row["name"], row.get("state", "-"), row.get("ipv4") or "-",
                           row.get("ipv6") or "-", row.get("mac") or "-",
                           row.get("speed") or "-"] for row in info.interfaces])
        if info.runtimes:
            report.kv("Runtime versions", list(info.runtimes.items()))
        if show_packages and info.packages:
            report.kv("Packages", list(info.packages.items()))
        if show_tools and info.tools:
            report.table("Security tools", ["Tool", "State"],
                         [[name, state] for name, state in sorted(info.tools.items())])
        report.findings(result.findings, "Posture findings")
        report.note("system", {
            "os": info.os_name,
            "kernel": info.kernel,
            "hostname": info.hostname,
            "elevated": info.elevated,
            "memory_percent": info.mem_percent,
        })


def local_networks() -> dict[str, str]:
    """``{interface: network_cidr}`` for global IPv4 addresses."""
    networks: dict[str, str] = {}
    for row in interfaces():
        cidr = row.get("ipv4") or ""
        if not cidr or "/" not in cidr:
            continue
        try:
            network = ipaddress.ip_interface(cidr).network
        except ValueError:
            continue
        if network.is_loopback:
            continue
        networks[row["name"]] = str(network)
    return networks
