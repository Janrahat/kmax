"""Shared helpers: target parsing, port specifications, CIDR expansion, shelling out.

This module is deliberately dependency-free. Every helper that can fail raises
``TargetError`` (a ``ValueError`` subclass) so the CLI can turn bad input into a
clean exit code 2 message instead of a traceback.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass

__all__ = [
    "TargetError", "Target", "COMMON_PORTS", "TOP_100_PORTS", "parse_target",
    "parse_cidr", "parse_ports", "service_for", "guess_network", "have", "run",
    "read_text", "read_lines", "is_root", "human_bytes", "human_time",
    "is_private", "reverse_dns", "cli_snapshot",
]

# --------------------------------------------------------------------------- #
# Well-known services (fallback when no service database entry exists)
# --------------------------------------------------------------------------- #
COMMON_PORTS: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    67: "dhcp", 69: "tftp", 80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 500: "isakmp", 512: "exec", 513: "login", 514: "shell",
    515: "printer", 548: "afp", 554: "rtsp", 587: "submission", 623: "ipmi",
    631: "ipp", 636: "ldaps", 873: "rsync", 902: "vmware-auth", 993: "imaps",
    995: "pop3s", 1080: "socks", 1099: "rmi", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2181: "zookeeper", 2222: "ssh-alt", 2375: "docker", 2376: "docker-ssl",
    3000: "grafana/node", 3128: "squid", 3260: "iscsi", 3306: "mysql",
    3389: "rdp", 3690: "svn", 4369: "epmd", 4444: "metasploit", 4505: "salt",
    4506: "salt-master", 5000: "http-alt", 5060: "sip", 5432: "postgresql",
    5555: "adb", 5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb",
    5985: "winrm-http", 5986: "winrm-https", 6000: "x11", 6379: "redis",
    6443: "kubernetes", 7001: "weblogic", 7077: "spark", 8000: "http-alt",
    8008: "http-alt", 8009: "ajp13", 8080: "http-proxy", 8081: "http-alt",
    8086: "influxdb", 8161: "activemq", 8443: "https-alt", 8888: "http-alt",
    9000: "php-fpm", 9090: "prometheus", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch", 9418: "git", 10000: "webmin", 11211: "memcached",
    15672: "rabbitmq-mgmt", 27017: "mongodb", 27018: "mongodb", 50000: "db2",
    50070: "hdfs", 61616: "activemq-msg",
}

# nmap's classic "top 100" list, kept short and readable.
TOP_100_PORTS: list[int] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025,
    1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3260, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
    6379, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9200,
    9999, 10000, 11211, 27017, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

# A practical "top 1000": the classic list plus a curated, service-dense range.
_EXTRA_PORTS = sorted({
    *range(1, 1025),
    1080, 1099, 1158, 1200, 1241, 1311, 1352, 1433, 1434, 1521, 1524, 1556,
    1580, 1701, 1720, 1723, 1741, 1755, 1801, 1812, 1839, 1863, 1900, 1914,
    1935, 1947, 2000, 2001, 2002, 2003, 2049, 2121, 2179, 2222, 2251, 2301,
    2323, 2375, 2376, 2381, 2404, 2480, 2525, 2557, 2601, 2604, 2638, 2809,
    2869, 2967, 3000, 3001, 3005, 3011, 3030, 3052, 3128, 3260, 3268, 3269,
    3283, 3300, 3301, 3306, 3322, 3333, 3351, 3367, 3389, 3404, 3476, 3493,
    3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784,
    3800, 3801, 3809, 3814, 3826, 3851, 3869, 3871, 3878, 3880, 3889, 3905,
    3914, 3918, 3920, 3945, 3971, 3995, 3998, 4000, 4001, 4002, 4003, 4004,
    4005, 4006, 4045, 4111, 4125, 4129, 4224, 4242, 4279, 4321, 4343, 4443,
    4444, 4445, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001,
    5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080,
    5087, 5100, 5101, 5102, 5120, 5190, 5200, 5221, 5222, 5225, 5226, 5269,
    5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550,
    5555, 5560, 5566, 5631, 5633, 5666, 5672, 5678, 5679, 5718, 5730, 5800,
    5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900,
    5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5912, 5915, 5922, 5925,
    5950, 5952, 5959, 5960, 5961, 5962, 5963, 5984, 5985, 5986, 5987, 5988,
    5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009,
    6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6379, 6389,
    6443, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667,
    6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901,
    6969, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200,
    7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778,
    7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008,
    8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083,
    8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8161, 8180,
    8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333,
    8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800,
    8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040,
    9050, 9071, 9080, 9081, 9090, 9091, 9092, 9099, 9100, 9101, 9102, 9103,
    9110, 9111, 9200, 9207, 9220, 9290, 9300, 9415, 9418, 9485, 9500, 9535,
    9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917,
    9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004,
    10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566,
    10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11211,
    11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000,
    14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15672, 15742,
    16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877,
    17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801,
    19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502,
    24444, 24800, 25734, 25735, 26214, 27000, 27017, 27018, 27352, 27353,
    27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768,
    32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778,
    32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571,
    34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442,
    44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157,
    49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400,
    49999, 50000, 50001, 50002, 50003, 50006, 50070, 50300, 50389, 50500,
    50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328,
    55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020,
    60443, 61532, 61616, 61900, 62078, 63331, 64623, 64680, 65000, 65129,
    65389,
})
TOP_1000_PORTS: list[int] = sorted({*TOP_100_PORTS, *_EXTRA_PORTS})[:1000]

WEB_PORTS = [80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9443]

_PORT_ALIASES: dict[str, list[int]] = {
    "common": sorted(set(TOP_100_PORTS)),
    "top100": sorted(set(TOP_100_PORTS)),
    "top-100": sorted(set(TOP_100_PORTS)),
    "top1000": TOP_1000_PORTS,
    "top-1000": TOP_1000_PORTS,
    "web": WEB_PORTS,
    "all": list(range(1, 65536)),
    "full": list(range(1, 65536)),
}


class TargetError(ValueError):
    """Raised when a host, CIDR or port specification cannot be understood."""


# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Target:
    """A parsed target: IP literal, hostname or localhost."""

    raw: str
    host: str
    is_ip: bool
    address: str | None = None
    port: int | None = None
    scheme: str = ""

    def display(self) -> str:
        if self.is_ip:
            return self.host
        if self.address and self.address != self.host:
            return f"{self.host} ({self.address})"
        return self.host


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip().strip("[]"))
        return True
    except ValueError:
        return False


def is_private(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def resolve(host: str, timeout: float = 3.0) -> str | None:
    """Resolve a hostname to one IPv4 address (best effort)."""
    host = host.strip().strip("[]")
    if is_ip(host):
        return host
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(host)
    except (socket.gaierror, socket.herror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(previous)


def reverse_dns(address: str, timeout: float = 3.0) -> str:
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(address)
        return name.rstrip(".")
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(previous)


_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9.])?$")


def parse_target(raw: str, do_resolve: bool = False) -> Target:
    """Parse ``host``, ``host:port``, ``http://host/path`` or an IP literal.

    Resolution is *not* performed unless ``do_resolve`` is true, because a
    module may want to report ``NXDOMAIN`` itself instead of failing early.
    """
    if not raw or not raw.strip():
        raise TargetError("empty target")

    text = raw.strip()
    scheme = ""
    port: int | None = None

    if "://" in text:
        from urllib.parse import urlsplit

        parts = urlsplit(text)
        scheme = parts.scheme.lower()
        host = parts.hostname or ""
        if parts.port:
            port = parts.port
        text = host
        if not text:
            raise TargetError(f"could not extract a host from {raw!r}")

    # host:port (avoid IPv6 literals, which contain multiple colons)
    if text.count(":") == 1 and "://" not in raw:
        host, _, port_text = text.partition(":")
        if port_text.isdigit():
            port = int(port_text)
            if not 1 <= port <= 65535:
                raise TargetError(f"port out of range in {raw!r}")
            text = host
    elif text.startswith("[") and "]" in text:
        host, _, rest = text.partition("]")
        text = host.lstrip("[")
        rest = rest.lstrip(":")
        if rest.isdigit():
            port = int(rest)

    text = text.strip().strip("[]")
    if not text or any(ch.isspace() for ch in text):
        raise TargetError(f"invalid target {raw!r}")

    ip_literal = is_ip(text)
    if not ip_literal:
        if not _HOSTNAME_RE.match(text):
            raise TargetError(f"invalid hostname {text!r}")
        if "." not in text and text.lower() != "localhost":
            raise TargetError(
                f"{text!r} is not an IP address, FQDN or localhost"
            )

    address = text if ip_literal else (resolve(text) if do_resolve else None)
    return Target(raw=raw, host=text, is_ip=ip_literal, address=address,
                  port=port, scheme=scheme)


def parse_cidr(cidr: str, max_hosts: int = 4096) -> list[str]:
    """Expand a CIDR (or a single IP) into host addresses, capped for safety."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise TargetError(f"invalid CIDR {cidr!r}: {exc}") from exc
    if net.version != 4:
        raise TargetError("only IPv4 networks are supported for sweeps")
    if net.num_addresses > max_hosts + 2:
        raise TargetError(
            f"{cidr} holds {net.num_addresses} addresses, above the {max_hosts} "
            "host safety cap - use a narrower range"
        )
    return [str(host) for host in net.hosts()]


def guess_network(address: str, prefix: int = 24) -> str | None:
    """Return the /prefix network containing ``address``."""
    try:
        return str(ipaddress.ip_interface(f"{address}/{prefix}").network)
    except ValueError:
        return None


def local_addresses() -> dict[str, str]:
    """``{iface: cidr}`` for up, non-loopback IPv4 interfaces (uses ``ip``)."""
    result: dict[str, str] = {}
    rc, out, _ = run(["ip", "-o", "-4", "addr", "show", "scope", "global"], timeout=8)
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "inet":
                result[parts[1]] = parts[3]
    return result


# --------------------------------------------------------------------------- #
# Ports
# --------------------------------------------------------------------------- #
def parse_ports(spec: str | None = None, top: int | None = None) -> list[int]:
    """Parse ``80,443,8000-8100`` or an alias into a sorted port list.

    Recognised aliases: ``common``, ``top100``, ``top1000``, ``web``, ``all``.
    """
    if top:
        if top <= 100:
            return sorted(set(TOP_100_PORTS))[:top]
        return sorted(set(TOP_1000_PORTS))[:top]
    if not spec or not spec.strip():
        return sorted(set(TOP_100_PORTS))

    spec = spec.strip().lower().replace(" ", "")
    if spec in _PORT_ALIASES:
        return list(_PORT_ALIASES[spec])

    ports: set[int] = set()
    for chunk in spec.split(","):
        if not chunk:
            continue
        if "-" in chunk:
            low_text, _, high_text = chunk.partition("-")
            if not (low_text.isdigit() and high_text.isdigit()):
                raise TargetError(f"invalid port range {chunk!r}")
            low, high = int(low_text), int(high_text)
            if low > high:
                low, high = high, low
            if low < 1 or high > 65535:
                raise TargetError(f"ports must be within 1-65535 (got {chunk!r})")
            ports.update(range(low, high + 1))
        else:
            if not chunk.isdigit():
                raise TargetError(f"invalid port token {chunk!r}")
            value = int(chunk)
            if not 1 <= value <= 65535:
                raise TargetError(f"port out of range: {value}")
            ports.add(value)

    if not ports:
        raise TargetError("no ports selected")
    return sorted(ports)


def service_for(port: int, proto: str = "tcp") -> str:
    name = COMMON_PORTS.get(port)
    if name:
        return name
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


# --------------------------------------------------------------------------- #
# System helpers
# --------------------------------------------------------------------------- #
def have(cmd: str) -> bool:
    """True when ``cmd`` is on ``PATH``."""
    return shutil.which(cmd) is not None


def run(cmd: list[str], timeout: float = 30.0, stdin: str | None = None) -> tuple[int, str, str]:
    """Run a command without a shell. Returns ``(rc, stdout, stderr)``."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            input=stdin,
            timeout=timeout,
            check=False,
            errors="replace",
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: command not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{cmd[0]}: timed out after {timeout:g}s"
    except Exception as exc:  # pragma: no cover - defensive
        return 1, "", str(exc)


def read_text(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return default


def read_lines(path: str) -> list[str]:
    text = read_text(path)
    return [line.strip() for line in text.splitlines() if line.strip()]


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover - non-POSIX
        return False


def human_bytes(num: float) -> str:
    value = float(num or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(value) < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} EiB"


def human_time(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def rows_to_csv(rows: list[list[object]], delimiter: str = ",") -> str:
    import csv
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL)
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()


def cli_snapshot(argv: list[str] | None = None) -> str:
    """Shell-quote an argv list back into a copy-pasteable command."""
    import shlex

    args = list(argv if argv is not None else os.sys.argv)
    return " ".join(shlex.quote(part) for part in args)
