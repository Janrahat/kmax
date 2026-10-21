"""KMAX - Kali Multi-tool eXplorer.

A modular, dependency-light network and system reconnaissance toolkit for Kali
Linux, written in pure Python 3 (standard library only).

Quick start
-----------
    from kmax.modules import portscan

    result = portscan.execute(portscan.PortOptions(host="127.0.0.1",
                                                  ports=[22, 80, 443]))
    for port in result.ports:
        print(port.port, port.service)

Authorised testing only.
"""

from __future__ import annotations

__version__ = "2.0.0"
__author__ = "KMAX contributors"
__license__ = "MIT"
__all__ = ["__version__", "main"]


def main(argv: list[str] | None = None) -> int:
    """Convenience wrapper so ``python -m kmax`` and ``kmax`` behave the same."""
    from .cli import main as _main

    return _main(argv)
