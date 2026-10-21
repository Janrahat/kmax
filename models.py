"""Typed data containers shared by every KMAX module.

All results are plain dataclasses so that they serialise to JSON with
``dataclasses.asdict`` and stay easy to unit-test.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

__all__ = [
    "PortResult", "HostResult", "DNSAnswer", "CertInfo", "HTTPResult",
    "Finding", "SysInfo", "ScanMeta", "SEVERITY_ORDER", "SEVERITY_WEIGHT",
]

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "good")
SEVERITY_WEIGHT = {
    "critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0, "good": 0,
}


# --------------------------------------------------------------------------- #
# Network
# --------------------------------------------------------------------------- #
@dataclass
class PortResult:
    """A single probed TCP/UDP port."""

    port: int
    state: str = "closed"
    service: str = "unknown"
    protocol: str = "tcp"
    banner: str = ""
    version: str = ""
    latency_ms: float = 0.0

    def to_row(self) -> list[Any]:
        return [self.port, self.protocol, self.state, self.service,
                self.version or "-", self.banner or "-"]


@dataclass
class HostResult:
    """A host discovered during a sweep or a single-host probe."""

    address: str
    state: str = "unknown"
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    latency_ms: float = 0.0
    method: str = ""
    ports: list[PortResult] = field(default_factory=list)

    def to_row(self) -> list[Any]:
        return [self.address, self.hostname or "-", self.state,
                self.mac or "-", self.vendor or "-",
                f"{self.latency_ms:.1f}ms" if self.latency_ms else "-",
                self.method or "-"]


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #
@dataclass
class DNSAnswer:
    record_type: str
    value: str
    ttl: int | None = None
    name: str = ""

    def to_row(self) -> list[Any]:
        return [self.record_type, self.value, self.ttl if self.ttl is not None else "-"]


# --------------------------------------------------------------------------- #
# Web
# --------------------------------------------------------------------------- #
@dataclass
class CertInfo:
    """X.509 facts extracted from a TLS handshake."""

    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    days_remaining: int | None = None
    sans: list[str] = field(default_factory=list)
    version: int = 0
    signature_algorithm: str = ""
    key_size: int | None = None
    protocol: str = ""
    cipher: str = ""
    self_signed: bool = False
    wildcard: bool = False

    def to_row(self) -> list[Any]:
        return [self.subject, self.issuer, self.not_after,
                self.days_remaining if self.days_remaining is not None else "-",
                "yes" if self.self_signed else "no"]


@dataclass
class HTTPResult:
    url: str
    status: int = 0
    reason: str = ""
    elapsed_ms: float = 0.0
    length: int = 0
    title: str = ""
    server: str = ""
    powered_by: str = ""
    content_type: str = ""
    final_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    redirect_chain: list[str] = field(default_factory=list)
    cert: CertInfo | None = None
    findings: list["Finding"] = field(default_factory=list)

    def to_row(self) -> list[Any]:
        return [self.url, self.status or "-", self.server or "-",
                f"{self.elapsed_ms:.0f}ms" if self.elapsed_ms else "-",
                self.length or "-", self.content_type or "-"]


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """One security or hardening observation."""

    title: str
    severity: str = "info"
    detail: str = ""
    remediation: str = ""
    refs: list[str] = field(default_factory=list)
    source: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_row(self) -> list[Any]:
        return [self.severity.upper(), self.title, self.detail or "-",
                self.remediation or "-"]


# --------------------------------------------------------------------------- #
# System
# --------------------------------------------------------------------------- #
@dataclass
class SysInfo:
    """Normalised local system facts (populated by ``modules.sysinfo``)."""

    os_name: str = ""
    kernel: str = ""
    architecture: str = ""
    hostname: str = ""
    user: str = ""
    elevated: bool = False
    uptime: str = ""
    boot_time: str = ""
    cpu_model: str = ""
    cpu_cores: int = 0
    cpu_mhz: float = 0.0
    mem_total: float = 0.0
    mem_used: float = 0.0
    mem_percent: float = 0.0
    swap_total: float = 0.0
    swap_used: float = 0.0
    disks: list[dict[str, Any]] = field(default_factory=list)
    interfaces: list[dict[str, Any]] = field(default_factory=list)
    gateway: str = ""
    dns_servers: list[str] = field(default_factory=list)
    public_ip: str = ""
    packages: dict[str, str] = field(default_factory=dict)
    runtimes: dict[str, str] = field(default_factory=dict)
    tools: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #
@dataclass
class ScanMeta:
    """Provenance block attached to every report."""

    tool: str = "kmax"
    version: str = ""
    module: str = ""
    target: str = ""
    command: str = ""
    started: str = ""
    finished: str = ""
    duration_s: float = 0.0
    host: str = ""
    user: str = ""
    elevated: bool = False
    argv: list[str] = field(default_factory=list)
