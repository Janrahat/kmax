"""DNS intelligence: record enumeration, AXFR check, subdomain brute force, rDNS.

Two backends
------------
``dnspython`` (optional)  - used automatically when importable.
``built-in UDP client``   - a compact, dependency-free resolver used otherwise,
                            so ``kmax dns`` works on a bare Kali install.

Zone transfers are attempted with ``dig`` when present; the module reports
"not tested" rather than "safe" when ``dig`` is missing.
"""

from __future__ import annotations

import asyncio
import random
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from ..core import ui
from ..core.models import DNSAnswer, Finding, ScanMeta
from ..core.utils import read_lines, reverse_dns, run

__all__ = [
    "DNSOptions", "DNSResult", "execute", "render", "SUBDOMAIN_WORDLIST",
    "query", "build_query", "parse_response", "zone_transfer", "reverse_lookup",
    "enumerate_subdomains", "DEFAULT_RECORD_TYPES",
]

DEFAULT_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA")

_QTYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
    "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257, "ANY": 255,
}
_TYPE_NAMES = {value: key for key, value in _QTYPES.items()}

RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
    5: "REFUSED", 9: "NOTAUTH", 10: "NOTZONE",
}

# A pragmatic wordlist: web, mail, infra, CI/CD, monitoring and common admin names.
SUBDOMAIN_WORDLIST: list[str] = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp", "ssh",
    "vpn", "vpn2", "remote", "gateway", "ns1", "ns2", "ns3", "dns", "dns1",
    "mx", "mx1", "mx2", "api", "api-v2", "dev", "staging", "stage", "test",
    "qa", "uat", "demo", "sandbox", "preview", "admin", "portal", "intranet",
    "internal", "cpanel", "whm", "webdisk", "autodiscover", "autoconfig",
    "git", "gitlab", "github", "bitbucket", "jenkins", "ci", "cd", "build",
    "docker", "registry", "k8s", "kubernetes", "rancher", "openshift",
    "grafana", "prometheus", "kibana", "elastic", "elasticsearch", "monitor",
    "monitoring", "status", "metrics", "sentry", "zabbix", "nagios",
    "db", "database", "mysql", "postgres", "postgresql", "redis", "mongo",
    "mongodb", "backup", "bak", "archive", "cdn", "static", "assets", "media",
    "img", "images", "files", "download", "downloads", "upload", "uploads",
    "docs", "wiki", "confluence", "blog", "shop", "store", "pay", "payment",
    "billing", "invoice", "sso", "auth", "login", "id", "accounts", "oauth",
    "app", "apps", "mobile", "m", "wap", "beta", "old", "new", "v2", "legacy",
    "exchange", "owa", "lyncdiscover", "sip", "sip1", "meet", "chat", "talk",
    "support", "helpdesk", "help", "tickets", "crm", "erp", "hr", "finance",
    "proxy", "squid", "cache", "ldap", "ad", "dc1", "dc2", "fs", "print",
    "printer", "scanner", "camera", "nvr", "iot", "nas", "webdav", "vpn-gw",
    "extranet", "partners", "clients", "customer", "api-docs", "swagger",
    "graphql", "ws", "websocket", "mqtt", "broker", "kafka", "rabbitmq",
]


# --------------------------------------------------------------------------- #
# Options / result containers
# --------------------------------------------------------------------------- #
@dataclass
class DNSOptions:
    domain: str
    record_types: tuple[str, ...] = DEFAULT_RECORD_TYPES
    resolver: str = ""
    timeout: float = 3.0
    do_axfr: bool = True
    do_subdomains: bool = False
    wordlist: list[str] = field(default_factory=list)
    workers: int = 60
    wildcard_check: bool = True


@dataclass
class DNSResult:
    domain: str
    resolver: str = ""
    answers: list[DNSAnswer] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    mail_servers: list[str] = field(default_factory=list)
    text_records: list[str] = field(default_factory=list)
    axfr_records: list[str] = field(default_factory=list)
    axfr_tested: bool = False
    subdomains: list[tuple[str, str]] = field(default_factory=list)
    wildcard: str = ""
    reverse: list[tuple[str, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    backend: str = ""
    elapsed_s: float = 0.0

    def addresses(self) -> list[str]:
        return [a.value for a in self.answers if a.record_type == "A"]


# --------------------------------------------------------------------------- #
# Built-in DNS client
# --------------------------------------------------------------------------- #
def build_query(name: str, qtype: str = "A", txid: int | None = None) -> bytes:
    """Encode a single-question DNS query packet."""
    txid = random.randint(0, 0xFFFF) if txid is None else txid & 0xFFFF
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = bytearray()
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        try:
            encoded = label.encode("idna")[:63]
        except (UnicodeError, UnicodeEncodeError):
            encoded = label.encode("ascii", errors="ignore")[:63]
        if not encoded:
            continue
        qname.append(len(encoded))
        qname.extend(encoded)
    qname.append(0)
    return header + bytes(qname) + struct.pack(">HH", _QTYPES.get(qtype.upper(), 1), 1)


def _decode_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name; returns ``(name, next_offset)``."""
    labels: list[str] = []
    if depth > 12:
        return "", offset + 1
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                break
            pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            suffix, _ = _decode_name(data, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            offset += 2
            break
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(part for part in labels if part), offset


def _parse_txt(rdata: bytes) -> str:
    chunks: list[str] = []
    index = 0
    while index < len(rdata):
        length = rdata[index]
        chunks.append(rdata[index + 1:index + 1 + length].decode("utf-8", "replace"))
        index += 1 + length
    return "".join(chunks)


def parse_response(data: bytes) -> tuple[list[DNSAnswer], dict[str, Any]]:
    """Parse a DNS response into ``(answers, metadata)``."""
    if len(data) < 12:
        return [], {"rcode": 2, "rcode_name": "SERVFAIL"}

    _txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0x000F
    meta: dict[str, Any] = {
        "rcode": rcode,
        "rcode_name": RCODE_NAMES.get(rcode, str(rcode)),
        "authoritative": bool(flags & 0x0400),
        "truncated": bool(flags & 0x0200),
        "recursion_available": bool(flags & 0x0080),
        "ancount": ancount,
    }

    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_name(data, offset)
        offset += 4

    answers: list[DNSAnswer] = []

    def read_section(count: int, offset: int, section: str) -> int:
        for _ in range(count):
            if offset >= len(data):
                break
            name, offset = _decode_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata_offset = offset
            rdata = data[offset:offset + rdlength]
            offset += rdlength

            type_name = _TYPE_NAMES.get(rtype, f"TYPE{rtype}")
            try:
                if rtype == 1 and len(rdata) == 4:
                    value = ".".join(str(byte) for byte in rdata)
                elif rtype == 28 and len(rdata) == 16:
                    value = socket.inet_ntop(socket.AF_INET6, rdata)
                elif rtype in (2, 5, 12):
                    value, _ = _decode_name(data, rdata_offset)
                elif rtype == 15:
                    preference = struct.unpack(">H", rdata[:2])[0]
                    exchange, _ = _decode_name(data, rdata_offset + 2)
                    value = f"{preference} {exchange}"
                elif rtype == 6:
                    mname, cursor = _decode_name(data, rdata_offset)
                    rname, cursor = _decode_name(data, cursor)
                    serial = struct.unpack(">I", data[cursor:cursor + 4])[0] if cursor + 4 <= len(data) else 0
                    value = f"{mname} {rname} serial={serial}"
                elif rtype == 16:
                    value = _parse_txt(rdata)
                elif rtype == 33:
                    priority, weight, port = struct.unpack(">HHH", rdata[:6])
                    target, _ = _decode_name(data, rdata_offset + 6)
                    value = f"{priority} {weight} {port} {target}"
                elif rtype == 257:
                    flags_value = rdata[0] if rdata else 0
                    tag_length = rdata[1] if len(rdata) > 1 else 0
                    tag = rdata[2:2 + tag_length].decode("utf-8", "replace")
                    rest = rdata[2 + tag_length:].decode("utf-8", "replace")
                    value = f"{tag} {rest}".strip()
                else:
                    value = rdata.hex()
            except Exception:
                value = rdata.hex()

            if section == "answer":
                answers.append(DNSAnswer(record_type=type_name, value=value, ttl=ttl,
                                         name=name))
        return offset

    offset = read_section(ancount, offset, "answer")
    offset = read_section(nscount, offset, "authority")
    read_section(arcount, offset, "additional")
    return answers, meta


def _system_resolver() -> str:
    for line in read_lines("/etc/resolv.conf"):
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) > 1:
                return parts[1]
    return "8.8.8.8"


def _query_builtin(name: str, qtype: str, server: str, timeout: float) -> tuple[list[DNSAnswer], dict[str, Any]]:
    packet = build_query(name, qtype)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(4096)
    except socket.timeout:
        return [], {"rcode": 2, "rcode_name": "TIMEOUT", "ancount": 0}
    except OSError as exc:
        return [], {"rcode": 2, "rcode_name": f"ERROR:{exc.errno}", "ancount": 0}
    if not data:
        return [], {"rcode": 2, "rcode_name": "EMPTY", "ancount": 0}
    return parse_response(data)


def query(name: str, qtype: str = "A", server: str = "", timeout: float = 3.0
          ) -> tuple[list[DNSAnswer], dict[str, Any]]:
    """Query one record type; tries dnspython first, then the built-in client."""
    resolver = server or _system_resolver()
    try:
        import dns.resolver  # type: ignore

        config = dns.resolver.Resolver(configure=not bool(server))
        if server:
            config.nameservers = [server]
        config.timeout = timeout
        config.lifetime = timeout * 1.5
        answers: list[DNSAnswer] = []
        try:
            response = config.resolve(name, qtype, raise_on_no_answer=False)
        except Exception:
            return [], {"rcode": 3, "rcode_name": "NXDOMAIN", "ancount": 0}
        if response.rrset is not None:
            for record in response.rrset:
                answers.append(DNSAnswer(
                    record_type=qtype.upper(),
                    value=record.to_text().rstrip("."),
                    ttl=response.rrset.ttl,
                    name=name,
                ))
        return answers, {"rcode": 0, "rcode_name": "NOERROR",
                         "ancount": len(answers), "backend": "dnspython"}
    except ImportError:
        pass
    return _query_builtin(name, qtype, resolver, timeout)


def backend_name() -> str:
    try:
        import dns.resolver  # type: ignore  # noqa: F401

        return "dnspython"
    except ImportError:
        return "builtin-udp"


# --------------------------------------------------------------------------- #
# Zone transfer
# --------------------------------------------------------------------------- #
def zone_transfer(domain: str, nameservers: Sequence[str],
                  timeout: float = 6.0) -> tuple[list[str], bool]:
    """Attempt AXFR against each NS with ``dig``.

    Returns ``(records, tested)``; ``tested`` is False when ``dig`` is absent.
    """
    from ..core.utils import have

    if not have("dig"):
        ui.warn("dig is not installed - AXFR could not be tested (install dnsutils)")
        return [], False

    records: list[str] = []
    for server in nameservers:
        code, out, err = run(
            ["dig", f"@{server}", domain, "AXFR", "+time=4", "+tries=1", "+noall", "+answer"],
            timeout=timeout,
        )
        if code != 0:
            ui.debug(f"AXFR {server} failed: {err.strip()[:120]}")
            continue
        transferred = [line.split() for line in out.splitlines() if "\t" in line or " IN " in line]
        if "XFR size" in out or (transferred and "Transfer failed" not in out):
            for line in out.splitlines():
                if re.search(r"\sIN\s", line):
                    records.append(" ".join(line.split()))
        else:
            ui.debug(f"AXFR refused by {server}")
    return records, True


# --------------------------------------------------------------------------- #
# Subdomain enumeration
# --------------------------------------------------------------------------- #
def wildcard_address(domain: str, timeout: float = 3.0) -> str:
    """Detect wildcard DNS by resolving a random label."""
    probe = f"kmax-wildcard-{random.randint(100000, 999999)}.{domain}"
    addresses, _ = query(probe, "A", timeout=timeout)
    return addresses[0].value if addresses else ""


def enumerate_subdomains(domain: str, wordlist: Iterable[str], workers: int = 60,
                         timeout: float = 2.0, wildcard: str = "") -> list[tuple[str, str]]:
    """Resolve ``<word>.<domain>`` concurrently; returns ``[(fqdn, ip)]``."""
    words = list(wordlist)

    async def one(word: str) -> tuple[str, str] | None:
        fqdn = f"{word}.{domain}"
        try:
            infos = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(fqdn, None), timeout=timeout
            )
        except Exception:
            return None
        for family, _type, _proto, _canon, sockaddr in infos:
            if family == socket.AF_INET:
                address = sockaddr[0]
                if wildcard and address == wildcard:
                    return None
                return fqdn, address
        return None

    async def runner() -> list[tuple[str, str]]:
        semaphore = asyncio.Semaphore(max(1, workers))
        progress = ui.Progress(len(words), "subdomains")
        found: list[tuple[str, str]] = []

        async def guarded(word: str):
            async with semaphore:
                result = await one(word)
                progress.tick()
                return result

        for outcome in await asyncio.gather(*(guarded(word) for word in words)):
            if outcome:
                found.append(outcome)
        progress.close()
        return found

    return sorted(set(asyncio.run(runner())))


def reverse_lookup(address: str, server: str = "", timeout: float = 3.0) -> str:
    """PTR lookup with the built-in client, falling back to the system resolver."""
    try:
        import ipaddress

        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return ""
    if ip.version != 4:
        return ""
    pointer = ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"
    answers, _ = query(pointer, "PTR", server, timeout)
    if answers:
        return answers[0].value.rstrip(".")
    return reverse_dns(str(ip), timeout)


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def normalise_domain(raw: str) -> str:
    text = raw.strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    return text


def execute(opts: DNSOptions) -> DNSResult:
    """Enumerate DNS records and evaluate mail/DNS hardening."""
    domain = normalise_domain(opts.domain)
    if not domain or "." not in domain:
        raise ValueError(f"{opts.domain!r} is not a domain name")

    started = time.perf_counter()
    result = DNSResult(domain=domain, resolver=opts.resolver or _system_resolver(),
                       backend=backend_name())
    ui.info(f"querying {len(opts.record_types)} record type(s) for {domain} "
            f"via {result.resolver} ({result.backend})")

    seen: set[tuple[str, str]] = set()
    for record_type in opts.record_types:
        records, meta = query(domain, record_type, opts.resolver, opts.timeout)
        if not records:
            ui.debug(f"{record_type:<5} {meta.get('rcode_name', 'no answer')}")
        for record in records:
            key = (record.record_type, record.value)
            if key not in seen:
                seen.add(key)
                result.answers.append(record)
                ui.debug(f"{record.record_type:<5} {record.value}")

    result.nameservers = sorted({a.value.rstrip(".") for a in result.answers
                                 if a.record_type == "NS"})
    result.mail_servers = sorted({a.value.split()[-1].rstrip(".") for a in result.answers
                                  if a.record_type == "MX"})
    result.text_records = [a.value for a in result.answers if a.record_type == "TXT"]

    for address in result.addresses()[:5]:
        name = reverse_lookup(address, opts.resolver, opts.timeout)
        if name:
            result.reverse.append((address, name))

    if opts.wildcard_check:
        wildcard = wildcard_address(domain, opts.timeout)
        if wildcard:
            result.wildcard = wildcard
            ui.warn(f"wildcard DNS detected: *.{domain} -> {wildcard}")

    if opts.do_axfr and result.nameservers:
        ui.info(f"testing AXFR against {len(result.nameservers)} nameserver(s)…")
        records, tested = zone_transfer(domain, result.nameservers)
        result.axfr_records = records
        result.axfr_tested = tested

    if opts.do_subdomains:
        words = opts.wordlist or SUBDOMAIN_WORDLIST
        ui.info(f"brute-forcing {len(words)} subdomain label(s)…")
        result.subdomains = enumerate_subdomains(
            domain, words, opts.workers, max(1.0, opts.timeout),
            wildcard=result.wildcard,
        )

    result.findings = analyse(result)
    result.elapsed_s = round(time.perf_counter() - started, 3)
    return result


def analyse(result: DNSResult) -> list[Finding]:
    """Evaluate SPF, DMARC, DKIM, CAA, NS redundancy, AXFR and wildcard DNS."""
    findings: list[Finding] = []
    joined_txt = " ".join(result.text_records).lower()

    if result.answers:
        findings.append(Finding(
            title=f"{len(result.answers)} DNS record(s) published",
            severity="info",
            detail="Records: " + ", ".join(sorted({a.record_type for a in result.answers})),
            source="dnsenum",
        ))
    else:
        findings.append(Finding(
            title="No DNS records returned",
            severity="info",
            detail="The name may not exist, or the resolver timed out / refused the query.",
            remediation="Retry with --dns-server 1.1.1.1 to rule out a local resolver issue.",
            source="dnsenum",
        ))

    # --- e-mail authentication ---------------------------------------- #
    if not joined_txt:
        findings.append(Finding(
            title="No SPF record",
            severity="medium",
            detail="No TXT records at all, so SPF and DMARC are both absent - anyone "
                   "can spoof mail from this domain.",
            remediation='Publish "v=spf1 include:<your sender> -all" and a _dmarc '
                        'record with p=reject once you are confident.',
            source="dnsenum",
        ))
        findings.append(Finding(
            title="No DMARC policy",
            severity="medium",
            detail="Property of the apex TXT set: no DMARC policy was found.",
            remediation="Publish _dmarc TXT: v=DMARC1; p=none; rua=mailto:dmarc@domain.",
            source="dnsenum",
        ))
    else:
        if "v=spf1" in joined_txt:
            if "-all" in joined_txt:
                severity, detail = "good", "SPF ends with -all (hard fail)."
            elif "~all" in joined_txt:
                severity, detail = "low", "SPF ends with ~all (soft fail) - spoofed mail still lands."
            else:
                severity, detail = "medium", "SPF has no explicit all mechanism."
            findings.append(Finding(
                title="SPF record present", severity=severity, detail=detail,
                remediation="Prefer -all once every legitimate sender is listed.",
                source="dnsenum",
            ))
        else:
            findings.append(Finding(
                title="No SPF record", severity="medium",
                detail="No v=spf1 TXT record found for the apex domain.",
                remediation='Publish TXT "v=spf1 include:<provider> -all".',
                source="dnsenum",
            ))

        if "v=dmarc1" not in joined_txt:
            findings.append(Finding(
                title="No DMARC policy", severity="medium",
                detail="DMARC aligns SPF/DKIM and lets receivers reject spoofed mail.",
                remediation="Publish _dmarc TXT: v=DMARC1; p=none; rua=mailto:dmarc@domain "
                            "then move to p=quarantine/reject.",
                source="dnsenum",
            ))
        else:
            policy = re.search(r"p\s*=\s*(none|quarantine|reject)", joined_txt)
            policy_name = policy.group(1) if policy else "unknown"
            severity = {"reject": "good", "quarantine": "low", "none": "medium"}.get(
                policy_name, "low")
            findings.append(Finding(
                title=f"DMARC policy: p={policy_name}", severity=severity,
                detail="Monitors or enforces alignment for mail from this domain.",
                remediation="Progress to p=reject with an rua reporting address.",
                source="dnsenum",
            ))
        if "v=dkim1" not in joined_txt:
            findings.append(Finding(
                title="No DKIM selector visible in TXT",
                severity="low",
                detail="DKIM keys live under <selector>._domainkey, so this is only a hint.",
                remediation="Ensure every sending system signs with DKIM.",
                source="dnsenum",
            ))

    # --- transport / issuance ----------------------------------------- #
    if not any(record.record_type == "CAA" for record in result.answers):
        findings.append(Finding(
            title="No CAA record",
            severity="low",
            detail="Any public CA may issue certificates for this domain.",
            remediation="Add CAA records pinning issuance to your CA.",
            source="dnsenum",
        ))
    if not any(record.record_type == "AAAA" for record in result.answers):
        findings.append(Finding(
            title="No IPv6 (AAAA) record",
            severity="info",
            detail="The domain is IPv4-only, which is fine unless IPv6 is required.",
            source="dnsenum",
        ))

    # --- resilience ---------------------------------------------------- #
    if len(result.nameservers) == 1:
        findings.append(Finding(
            title="Single authoritative nameserver",
            severity="medium",
            detail=f"Only {result.nameservers[0]} serves this zone - one outage takes the domain down.",
            remediation="Run at least two nameservers on different networks/providers.",
            source="dnsenum",
        ))
    elif len(result.nameservers) >= 2:
        findings.append(Finding(
            title=f"{len(result.nameservers)} nameservers configured",
            severity="good",
            detail=", ".join(result.nameservers),
            source="dnsenum",
        ))

    if result.axfr_records:
        findings.append(Finding(
            title="Zone transfer (AXFR) succeeded",
            severity="critical",
            detail=f"{len(result.axfr_records)} records leaked by an authoritative server.",
            remediation="Restrict AXFR to secondary nameservers (allow-transfer / ACL).",
            source="dnsenum",
        ))
    elif result.axfr_tested:
        findings.append(Finding(
            title="Zone transfer refused",
            severity="good",
            detail="Every authoritative server refused AXFR.",
            source="dnsenum",
        ))

    if result.wildcard:
        findings.append(Finding(
            title="Wildcard DNS is enabled",
            severity="low",
            detail=f"*.{result.domain} resolves to {result.wildcard}; brute-force results "
                   "were filtered against it.",
            remediation="Confirm the wildcard is intentional; it can mask subdomain takeovers.",
            source="dnsenum",
        ))

    if result.subdomains:
        findings.append(Finding(
            title=f"{len(result.subdomains)} subdomain(s) resolve",
            severity="info",
            detail="Each live name widens the attack surface and should be inventoried.",
            remediation="Decommission unused records and monitor for takeover-prone CNAMEs.",
            source="dnsenum",
        ))
    return findings


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render(result: DNSResult, report=None) -> None:
    ui.section(f"DNS intelligence - {result.domain}", "\u25c6")
    ui.kv([
        ("Resolver", f"{result.resolver} ({result.backend})"),
        ("Records", len(result.answers)),
        ("Nameservers", ", ".join(result.nameservers) or "-"),
        ("Mail servers", ", ".join(result.mail_servers) or "-"),
        ("Wildcard", result.wildcard or "none"),
        ("Duration", f"{result.elapsed_s:.2f}s"),
    ])

    if result.answers:
        ui.section("Records", "\u25c8")
        grouped: dict[str, list[DNSAnswer]] = {}
        for record in result.answers:
            grouped.setdefault(record.record_type, []).append(record)
        for record_type in sorted(grouped):
            ui.plain(ui.c(f"  {record_type}", "bcyan", "bold"))
            for record in grouped[record_type]:
                ttl = f"{record.ttl}s" if record.ttl is not None else "-"
                ui.plain(f"    {record.value}  {ui.c('ttl ' + ttl, 'gray')}")
    elif not ui.is_quiet():
        ui.warn("no records returned")

    if result.reverse:
        ui.section("Reverse lookups", "\u25c8")
        ui.table(["Address", "PTR"], [list(item) for item in result.reverse])

    if result.subdomains:
        ui.section("Resolved subdomains", "\u25c8")
        ui.table(["Host", "Address"], [list(item) for item in result.subdomains])

    if result.axfr_records:
        ui.section("Zone transfer dump", "\u2691")
        ui.plain(ui.c("\n".join("  " + line for line in result.axfr_records[:60]), "gray"))
        if len(result.axfr_records) > 60:
            ui.plain(ui.c(f"  … {len(result.axfr_records) - 60} more record(s)", "gray"))

    if result.findings:
        ui.section("DNS & e-mail posture", "\u2691")
        for finding in result.findings:
            ui.plain(f"  {ui.severity_tag(finding.severity)} {finding.title}")
            if finding.detail:
                ui.plain(f"        {ui.c(finding.detail, 'gray')}")

    if report is not None:
        report.kv(f"DNS intelligence - {result.domain}", [
            ("Resolver", f"{result.resolver} ({result.backend})"),
            ("Records", len(result.answers)),
            ("Nameservers", ", ".join(result.nameservers) or "-"),
            ("Mail servers", ", ".join(result.mail_servers) or "-"),
            ("Wildcard", result.wildcard or "none"),
            ("AXFR tested", "yes" if result.axfr_tested else "no (dig missing)"),
            ("Duration", f"{result.elapsed_s:.2f}s"),
        ])
        report.table("Records", ["Type", "Value", "TTL"],
                     [[record.record_type, record.value,
                       record.ttl if record.ttl is not None else "-"]
                      for record in result.answers], limit=200)
        if result.reverse:
            report.table("Reverse lookups", ["Address", "PTR"],
                         [list(item) for item in result.reverse])
        if result.subdomains:
            report.table("Resolved subdomains", ["Host", "Address"],
                         [list(item) for item in result.subdomains])
        if result.axfr_records:
            report.text("Zone transfer dump", "\n".join(result.axfr_records))
        report.findings(result.findings, "DNS & e-mail posture")
        report.note("dns", {
            "nameservers": result.nameservers,
            "mail_servers": result.mail_servers,
            "addresses": result.addresses(),
            "wildcard": result.wildcard,
        })
