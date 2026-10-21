"""KMAX core package.

Holds everything that is shared between modules and is not itself a scan:
terminal rendering (:mod:`kmax.core.ui`), typed result containers
(:mod:`kmax.core.models`), pure helpers (:mod:`kmax.core.utils`) and the
multi-format report engine (:mod:`kmax.core.report`).
"""

from __future__ import annotations

from . import report, ui, utils  # noqa: F401  (re-exported convenience)
from .context import Runtime  # noqa: F401
from .models import (  # noqa: F401
    SEVERITY_ORDER,
    SEVERITY_WEIGHT,
    CertInfo,
    DNSAnswer,
    Finding,
    HostResult,
    HTTPResult,
    PortResult,
    ScanMeta,
    SysInfo,
)
from .report import Report, now_iso  # noqa: F401

__all__ = [
    "ui", "utils", "report", "Runtime", "Report", "now_iso",
    "PortResult", "HostResult", "DNSAnswer", "CertInfo", "HTTPResult",
    "Finding", "SysInfo", "ScanMeta", "SEVERITY_ORDER", "SEVERITY_WEIGHT",
]
