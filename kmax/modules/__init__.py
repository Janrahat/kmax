"""KMAX modules package.

Each module owns one capability and exposes the same three-part surface:

``Options``      - a dataclass with everything the scan needs
``execute(...)`` - pure logic, returns a typed result object
``render(...)``  - prints the human view and optionally fills a Report

The CLI layer (:mod:`kmax.cli`) only wires arguments to ``execute`` and
``render``; it never contains scanning logic itself.
"""

from __future__ import annotations

__all__ = ["dnsenum", "netscan", "portscan", "sysinfo", "webscan"]
