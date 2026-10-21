"""One runtime context object, threaded from the CLI down into every module.

Keeping the knobs in a single dataclass means the modules never read
``argparse`` namespaces directly and stay trivially testable: build a
``Runtime`` in a test, hand it to a module, assert on the result.
"""

from __future__ import annotations

import getpass
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Any

from .models import ScanMeta
from .report import now_iso
from .utils import cli_snapshot, have, is_root

__all__ = ["Runtime"]


@dataclass
class Runtime:
    """Display switches, timing budget and provenance for one invocation."""

    # display
    quiet: bool = False
    json_output: bool = False
    verbose: bool = False
    no_color: bool = False

    # networking budget
    timeout: float = 1.0
    workers: int = 200
    retries: int = 0
    resolve: bool = True

    # module behaviour
    use_nmap: bool = False
    banners: bool = True
    service_detect: bool = True
    udp: bool = False
    verbose_errors: bool = False

    # report wiring
    report_path: str = ""
    report_format: str = ""
    with_report: bool = True

    # provenance
    module: str = ""
    target: str = ""
    argv: list[str] = field(default_factory=list)
    started_ts: float = field(default_factory=time.time)

    # ------------------------------------------------------------------ #
    @property
    def elapsed(self) -> float:
        return time.time() - self.started_ts

    def command(self) -> str:
        return cli_snapshot(self.argv) if self.argv else " ".join(os.sys.argv)

    def make_meta(self, module: str | None = None, target: str = "") -> ScanMeta:
        """Build a provenance block for a report."""
        return ScanMeta(
            tool="kmax",
            version=_version(),
            module=module or self.module,
            target=target or self.target,
            command=self.command(),
            started=now_iso(),
            host=socket.gethostname(),
            user=_user(),
            elevated=is_root(),
            argv=list(self.argv),
        )

    def finish(self, report: Any, meta: ScanMeta | None = None) -> None:
        """Stamp duration/finish time on a report just before saving."""
        if meta is not None:
            meta.finished = now_iso()
            meta.duration_s = round(self.elapsed, 3)

    def tool_snapshot(self) -> dict[str, str]:
        """Which optional external helpers are available right now."""
        tools = {}
        for name in ("nmap", "dig", "openssl", "ping", "ip", "arp", "whois",
                     "traceroute", "curl"):
            tools[name] = "available" if have(name) else "missing"
        return tools


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - defensive
        return os.environ.get("USER", "unknown")


def _version() -> str:
    from .. import __version__

    return __version__
