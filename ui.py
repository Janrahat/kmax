"""Terminal UI layer for KMAX.

Everything visual lives here so that the scanning modules stay pure logic and
remain unit-testable without a terminal attached.

Standard library only: ANSI colour (auto-disabled when piped or when
``NO_COLOR`` is set), Unicode box tables with an ASCII fallback, progress
counters and severity tags.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from contextlib import contextmanager
from typing import Any, Iterable, Iterator, Sequence

__all__ = [
    "configure", "color_enabled", "is_quiet", "c", "width", "ok", "warn", "err",
    "info", "debug", "step", "plain", "banner", "section", "kv", "table", "hr",
    "Progress", "timer", "severity_tag", "SEVERITIES",
]

SEVERITIES = ("critical", "high", "medium", "low", "info", "good")

_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "gray": "\033[90m",
    "bred": "\033[91m",
    "bgreen": "\033[92m",
    "byellow": "\033[93m",
    "bblue": "\033[94m",
    "bmagenta": "\033[95m",
    "bcyan": "\033[96m",
    "bwhite": "\033[97m",
}

_USE_COLOR = (
    bool(getattr(sys.stdout, "isatty", lambda: False)())
    and os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM", "") != "dumb"
)
_QUIET = False
_UTF8 = "utf" in (getattr(sys.stdout, "encoding", "") or "").lower()


def configure(no_color: bool = False, quiet: bool = False) -> None:
    """Apply CLI-wide display switches (``--no-color`` / ``--quiet``)."""
    global _USE_COLOR, _QUIET
    if no_color:
        _USE_COLOR = False
    _QUIET = quiet


def color_enabled() -> bool:
    return _USE_COLOR


def is_quiet() -> bool:
    return _QUIET


def c(text: object, *styles: str) -> str:
    """Wrap ``text`` in ANSI styles; a no-op when colour is disabled."""
    text = str(text)
    if not _USE_COLOR or not styles:
        return text
    prefix = "".join(_CODES.get(s, "") for s in styles)
    return f"{prefix}{text}{_CODES['reset']}"


def width(default: int = 100) -> int:
    try:
        cols = shutil.get_terminal_size((default, 24)).columns
    except Exception:  # pragma: no cover - defensive
        cols = default
    return max(60, min(cols, 140))


# --------------------------------------------------------------------------- #
# Status helpers
# --------------------------------------------------------------------------- #
def _emit(prefix: str, style: str, message: str) -> None:
    if _QUIET:
        return
    print(f"{c(prefix, style)} {message}", flush=True)


def ok(message: str) -> None:
    _emit("[+]", "bgreen", message)


def warn(message: str) -> None:
    _emit("[!]", "byellow", message)


def err(message: str) -> None:
    _emit("[-]", "bred", message)


def info(message: str) -> None:
    _emit("[*]", "bcyan", message)


def debug(message: str) -> None:
    if os.environ.get("KMAX_DEBUG"):
        _emit("[.]", "gray", message)


def step(message: str) -> None:
    if _QUIET:
        return
    print(f"\n{c('==>', 'bmagenta', 'bold')} {c(message, 'bold')}", flush=True)


def plain(message: object = "") -> None:
    if not _QUIET:
        print(message, flush=True)


# --------------------------------------------------------------------------- #
# Banner / headings
# --------------------------------------------------------------------------- #
_BANNER = (
    r"  _  __ __  __    _    __  __",
    r" | |/ /|  \/  |  / \   \ \/ /",
    r" | ' / | |\/| | / _ \   \  / ",
    r" | . \ | |  | |/ ___ \  /  \ ",
    r" |_|\_\|_|  |_/_/   \_\/_/\_\ ",
)


def banner(subtitle: str = "Kali Multi-tool eXplorer", version: str = "") -> None:
    if _QUIET:
        return
    for line in _BANNER:
        print(c(line, "bcyan"))
    ver = f" v{version}" if version else ""
    print(c(f" {subtitle}{ver}", "gray"))
    hr()


def section(title: str, icon: str = "") -> None:
    if _QUIET:
        return
    label = f"{icon} {title}".strip()
    tail = max(4, width() - len(label) - 6)
    left = "\u250c\u2500 " if _UTF8 else "+-- "
    fill = ("\u2500" if _UTF8 else "-") * tail
    print()
    print(c(left + label + " ", "bblue", "bold") + c(fill, "gray"))


def kv(pairs: Sequence[tuple[str, Any]], indent: int = 2) -> None:
    """Two-column key/value list (no box: reads better for facts)."""
    pairs = [(str(k), v) for k, v in pairs]
    if not pairs or _QUIET:
        return
    key_w = max(len(k) for k, _ in pairs)
    pad = " " * indent
    for key, value in pairs:
        print(f"{pad}{c(key.ljust(key_w), 'cyan')} : {value}", flush=True)


def hr(char: str = "\u2500") -> None:
    if not _QUIET:
        print(c((char if _UTF8 else "-") * width(), "gray"), flush=True)


# --------------------------------------------------------------------------- #
# Tables
# --------------------------------------------------------------------------- #
def _clip(value: object, limit: int) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.replace("\r", " ").replace("\n", " ").split())
    if limit and len(text) > limit:
        text = text[: max(1, limit - 1)] + "\u2026"
    return text


def table(
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    limit: int = 64,
    aligns: Sequence[str] | None = None,
    style: str = "bwhite",
) -> None:
    """Render an aligned table; degrades to ASCII when UTF-8 is unavailable."""
    rows = list(rows)
    if _QUIET:
        return
    if not rows:
        print(c("  (no results)", "gray"))
        return

    cols = len(headers)
    cells: list[list[str]] = [
        [_clip(row[i] if i < len(row) else "", limit) for i in range(cols)]
        for row in rows
    ]
    widths = [max([len(str(headers[i]))] + [len(r[i]) for r in cells]) for i in range(cols)]
    aligns = list(aligns or ["left"] * cols)

    if _UTF8:
        tl, tm, tr = "\u250c", "\u252c", "\u2510"
        ml, mm, mr = "\u251c", "\u253c", "\u2524"
        bl, bm, br = "\u2514", "\u2534", "\u2518"
        v, h = "\u2502", "\u2500"
    else:
        tl = tm = tr = ml = mm = mr = bl = bm = br = "+"
        v, h = "|", "-"

    def rule(left: str, mid: str, right: str) -> str:
        return left + mid.join(h * (w + 2) for w in widths) + right

    print(c(rule(tl, tm, tr), "gray"))
    head = [f" {c(str(headers[i]).ljust(widths[i]), 'bcyan', 'bold')} " for i in range(cols)]
    print(v.join(head))
    print(c(rule(ml, mm, mr), "gray"))

    for row in cells:
        line = []
        for i, cell in enumerate(row):
            padded = cell.rjust(widths[i]) if aligns[i] == "right" else cell.ljust(widths[i])
            line.append(f" {c(padded, style)} ")
        print(v.join(line))
    print(c(rule(bl, bm, br), "gray"), flush=True)


# --------------------------------------------------------------------------- #
# Progress
# --------------------------------------------------------------------------- #
class Progress:
    """Single-line counter that only paints when stdout is a TTY."""

    def __init__(self, total: int, label: str = "working", enabled: bool = True) -> None:
        self.total = max(1, int(total))
        self.label = label
        self.done = 0
        self.enabled = (
            enabled
            and not _QUIET
            and bool(getattr(sys.stdout, "isatty", lambda: False)())
        )
        self._last = 0.0
        self._start = time.time()

    def tick(self, n: int = 1) -> None:
        self.done = min(self.total, self.done + n)
        if not self.enabled:
            return
        now = time.time()
        if now - self._last < 0.08 and self.done < self.total:
            return
        self._last = now
        pct = self.done * 100 // self.total
        bar_len = 26
        filled = bar_len * self.done // self.total
        if _UTF8:
            bar = "\u2588" * filled + "\u2591" * (bar_len - filled)
        else:
            bar = "#" * filled + "." * (bar_len - filled)
        elapsed = max(1e-6, now - self._start)
        rate = self.done / elapsed
        sys.stdout.write(
            f"\r  {c(self.label, 'gray')} {c(bar, 'bcyan')} {pct:3d}% "
            f"({self.done}/{self.total}) {rate:5.0f}/s   "
        )
        sys.stdout.flush()
        if self.done >= self.total:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def close(self) -> None:
        if self.enabled and self.done < self.total:
            sys.stdout.write("\n")
            sys.stdout.flush()


@contextmanager
def timer(label: str = "") -> Iterator[dict[str, float]]:
    """Context manager yielding a dict that receives ``elapsed`` seconds."""
    start = time.perf_counter()
    box: dict[str, float] = {"elapsed": 0.0}
    yield box
    box["elapsed"] = time.perf_counter() - start
    if label:
        debug(f"{label} finished in {box['elapsed']:.2f}s")


def severity_tag(sev: str) -> str:
    mapping = {
        "critical": ("CRIT", "bred"),
        "high": ("HIGH", "bred"),
        "medium": ("MED ", "byellow"),
        "low": ("LOW ", "bblue"),
        "info": ("INFO", "gray"),
        "good": (" OK ", "bgreen"),
    }
    label, style = mapping.get((sev or "info").lower(), ("INFO", "gray"))
    return c(f"[{label}]", style, "bold")
