"""Report engine: one in-memory result, four output formats.

Example
-------
    report = Report(meta, title="KMAX scan - 10.0.0.5")
    report.kv("Host", [("Address", "10.0.0.5")])
    report.table("Open ports", ["Port", "Service"], [[22, "ssh"]])
    report.findings([Finding("Telnet exposed", "critical")])
    report.save("out/scan.html")      # extension decides the format

Supported formats: ``json``, ``markdown`` (``md``), ``html``, ``csv``.
"""

from __future__ import annotations

import csv
import html
import io
import json
import os
import re
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from .models import SEVERITY_ORDER, SEVERITY_WEIGHT, Finding, ScanMeta

__all__ = ["Report", "now_iso", "FORMAT_EXTENSIONS", "format_for_path"]

FORMAT_EXTENSIONS = {
    "json": ".json",
    "markdown": ".md",
    "html": ".html",
    "csv": ".csv",
}

_EXT_FORMATS = {
    ".json": "json",
    ".md": "markdown",
    ".markdown": "markdown",
    ".html": "html",
    ".htm": "html",
    ".csv": "csv",
}


def now_iso() -> str:
    """UTC timestamp in ISO-8601 form, second precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_for_path(path: str, default: str = "html") -> str:
    return _EXT_FORMATS.get(os.path.splitext(path)[1].lower(), default)


def _slug(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()
    return cleaned or "section"


def _fmt(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        if value == int(value):
            return str(int(value))
        return f"{value:.2f}".rstrip("0").rstrip(".")
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_fmt(v) for v in value) or "-"
    if isinstance(value, dict):
        return "; ".join(f"{k}={_fmt(v)}" for k, v in value.items()) or "-"
    return str(value)


class Report:
    """Accumulates modules' output and serialises it to a file or stdout."""

    def __init__(self, meta: ScanMeta | None = None, title: str = "KMAX Report") -> None:
        self.meta = meta or ScanMeta()
        if not self.meta.started:
            self.meta.started = now_iso()
        self.title = title
        self.blocks: list[dict[str, Any]] = []
        self.data: dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # Building
    # ------------------------------------------------------------------ #
    def kv(self, title: str, pairs: Sequence[tuple[str, Any]]) -> None:
        pairs = [(str(k), _fmt(v)) for k, v in pairs if v not in ("", None)]
        if pairs:
            self.blocks.append({"type": "kv", "title": title, "pairs": pairs})

    def table(self, title: str, headers: Sequence[str],
              rows: Iterable[Sequence[Any]], note: str = "", limit: int = 0) -> None:
        materialised = [[_fmt(cell) for cell in row] for row in rows]
        truncated = 0
        if limit and len(materialised) > limit:
            truncated = len(materialised) - limit
            materialised = materialised[:limit]
        if truncated:
            note = (note + " " if note else "") + f"({truncated} further row(s) omitted)"
        self.blocks.append({
            "type": "table", "title": title, "headers": [str(h) for h in headers],
            "rows": materialised, "note": note,
        })

    def text(self, title: str, body: str) -> None:
        if body and body.strip():
            self.blocks.append({"type": "text", "title": title, "body": body.rstrip()})

    def findings(self, items: Sequence[Finding] | Iterable[Finding],
                 title: str = "Findings") -> None:
        materialised = [item.as_dict() for item in (items or [])]
        if materialised:
            materialised.sort(
                key=lambda row: SEVERITY_ORDER.index(row.get("severity", "info"))
                if row.get("severity") in SEVERITY_ORDER else len(SEVERITY_ORDER)
            )
            self.blocks.append({"type": "findings", "title": title, "rows": materialised})

    def note(self, key: str, value: Any) -> None:
        self.data[key] = value

    def add_findings(self, title: str, items: Sequence[Finding]) -> None:
        self.findings(items, title)

    def extend(self, other: "Report") -> None:
        """Merge another report's blocks (used by the aggregate commands)."""
        self.blocks.extend(other.blocks)
        self.data.update(other.data)

    def empty(self) -> bool:
        return not self.blocks

    # ------------------------------------------------------------------ #
    # Summary
    # ------------------------------------------------------------------ #
    def severity_counts(self) -> dict[str, int]:
        counts = {key: 0 for key in SEVERITY_ORDER}
        for block in self.blocks:
            if block["type"] == "findings":
                for row in block["rows"]:
                    severity = str(row.get("severity", "info")).lower()
                    counts[severity] = counts.get(severity, 0) + 1
        return counts

    def risk_score(self) -> int:
        """0-100 weighted risk score; higher means more risk."""
        total = sum(
            SEVERITY_WEIGHT.get(severity, 0) * count
            for severity, count in self.severity_counts().items()
        )
        return min(100, total)

    def all_findings(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for block in self.blocks:
            if block["type"] == "findings":
                rows.extend(block["rows"])
        return rows

    # ------------------------------------------------------------------ #
    # Serialisers
    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict[str, Any]:
        self.meta.finished = self.meta.finished or now_iso()
        return {
            "report": {
                "title": self.title,
                "generated": self.meta.finished,
                "risk_score": self.risk_score(),
                "severity": self.severity_counts(),
            },
            "meta": asdict(self.meta),
            "sections": self.blocks,
            "data": self.data,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False, default=str)

    def to_markdown(self) -> str:
        payload = self.to_dict()
        meta = payload["meta"]
        summary = payload["report"]
        lines = [f"# {self.title}", ""]

        lines += [
            "| Field | Value |",
            "| --- | --- |",
            f"| Tool | `{meta['tool']} {meta['version']}` |",
            f"| Module | `{meta['module'] or '-'}` |",
            f"| Target | `{meta['target'] or '-'}` |",
            f"| Started | {meta['started']} |",
            f"| Finished | {meta['finished']} |",
            f"| Duration | {meta['duration_s']:.2f}s |" if meta["duration_s"] else "| Duration | - |",
            f"| Analyst host | `{meta['host'] or '-'}` (elevated: {meta['elevated']}) |",
            f"| Risk score | **{summary['risk_score']}/100** |",
            "",
        ]

        if meta["command"]:
            lines += ["```bash", meta["command"], "```", ""]

        counts = summary["severity"]
        flagged = " · ".join(f"{k}: {v}" for k, v in counts.items() if v)
        if flagged:
            lines += [f"**Findings:** {flagged}", ""]

        if self.blocks:
            lines += ["## Contents", ""]
            for block in self.blocks:
                lines.append(f"- [{block['title']}](#{_slug(block['title'])})")
            lines.append("")

        for block in self.blocks:
            lines += [f"## {block['title']}", ""]
            kind = block["type"]
            if kind == "kv":
                width = max(len(k) for k, _ in block["pairs"])
                for key, value in block["pairs"]:
                    lines.append(f"- `{key.ljust(width)}` : {value}")
                lines.append("")
            elif kind == "text":
                lines += ["```", block["body"], "```", ""]
            elif kind == "table":
                headers = block["headers"]
                lines.append("| " + " | ".join(headers) + " |")
                lines.append("|" + "|".join(" --- " for _ in headers) + "|")
                for row in block["rows"]:
                    cells = [str(cell).replace("|", "\\|").replace("\n", " ") for cell in row]
                    lines.append("| " + " | ".join(cells) + " |")
                if block["note"]:
                    lines += ["", f"> {block['note']}"]
                lines.append("")
            elif kind == "findings":
                for row in block["rows"]:
                    lines.append(f"### [{row['severity'].upper()}] {row['title']}")
                    lines.append("")
                    if row.get("detail"):
                        lines.append(row["detail"])
                        lines.append("")
                    if row.get("remediation"):
                        lines += [f"**Remediation:** {row['remediation']}", ""]
                    if row.get("refs"):
                        lines += ["**References:** " + ", ".join(row["refs"]), ""]

        lines += [
            "---",
            "",
            "Generated by **KMAX**. Use only against systems you are authorised to test.",
            "",
        ]
        return "\n".join(lines)

    def to_csv(self) -> str:
        """Flatten every block into a single tidy CSV (section, kind, fields)."""
        buffer = io.StringIO()
        writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL)

        for block in self.blocks:
            kind = block["type"]
            if kind == "kv":
                writer.writerow(["section", "kind", "key", "value"])
                for key, value in block["pairs"]:
                    writer.writerow([block["title"], "kv", key, value])
            elif kind == "table":
                writer.writerow([block["title"], "table"] + list(block["headers"]))
                for row in block["rows"]:
                    writer.writerow([block["title"], "row"] + list(row))
            elif kind == "findings":
                writer.writerow([block["title"], "finding", "severity", "title",
                                 "detail", "remediation"])
                for row in block["rows"]:
                    writer.writerow([block["title"], "finding", row.get("severity", ""),
                                     row.get("title", ""), row.get("detail", ""),
                                     row.get("remediation", "")])
            elif kind == "text":
                writer.writerow([block["title"], "text"])
                for line in block["body"].splitlines():
                    writer.writerow([block["title"], "text", "", line])
        return buffer.getvalue()

    def to_html(self) -> str:
        payload = self.to_dict()
        meta = payload["meta"]
        summary = payload["report"]
        score = summary["risk_score"]
        counts = summary["severity"]
        tone = "#22c55e" if score < 15 else "#eab308" if score < 45 else "#ef4444"
        esc = html.escape

        parts: list[str] = [
            "<!doctype html>",
            '<html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{esc(self.title)}</title>",
            """<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin:0; background:#0a0e13; color:#d7e1ea;
  font:15px/1.65 ui-monospace,SFMono-Regular,"DejaVu Sans Mono",Menlo,Consolas,monospace; }
.wrap { max-width:1200px; margin:0 auto; padding:34px 20px 80px; }
header { border-bottom:1px solid #1d2937; padding-bottom:16px; margin-bottom:24px; }
h1 { font-size:25px; margin:0 0 8px; color:#e9f3fc; letter-spacing:.3px; }
h2 { font-size:15px; margin:32px 0 10px; color:#7dd3fc; text-transform:uppercase;
  letter-spacing:1.5px; border-left:3px solid #0ea5e9; padding-left:10px; }
h3 { font-size:13.5px; margin:16px 0 4px; color:#fbbf24; }
.sub { color:#7b8b9c; font-size:12.5px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
  gap:12px; margin:18px 0 6px; }
.card { background:#101a24; border:1px solid #1d2937; border-radius:10px; padding:13px 15px; }
.card .k { color:#6b7c8d; font-size:10.5px; text-transform:uppercase; letter-spacing:1.1px; }
.card .v { font-size:17px; color:#e9f3fc; margin-top:4px; word-break:break-word; }
table { width:100%; border-collapse:collapse; font-size:12.5px; margin:8px 0 4px;
  background:#0d161f; border:1px solid #1d2937; border-radius:8px; overflow:hidden; }
th { text-align:left; background:#14202e; color:#8fb6d6; font-weight:600; padding:9px 11px;
  font-size:10.5px; text-transform:uppercase; letter-spacing:.9px;
  border-bottom:1px solid #1d2937; white-space:nowrap; }
td { padding:8px 11px; border-bottom:1px solid #15202b; vertical-align:top;
  word-break:break-word; }
tr:last-child td { border-bottom:none; }
tr:hover td { background:#12202e; }
table.kv td:first-child { color:#8fb6d6; width:250px; white-space:nowrap; }
.note { color:#7b8b9c; font-size:11.5px; margin:4px 0 0; }
pre { background:#0d161f; border:1px solid #1d2937; border-radius:8px; padding:12px 14px;
  overflow:auto; font-size:12px; color:#b9c9d8; }
.sev { display:inline-block; padding:1px 8px; border-radius:999px; font-size:10px;
  font-weight:700; letter-spacing:.9px; text-transform:uppercase; }
.sev-critical,.sev-high { background:#3b1116; color:#ff909d; border:1px solid #7f1d2a; }
.sev-medium { background:#3a2b0b; color:#ffd479; border:1px solid #7c5a10; }
.sev-low { background:#0f2337; color:#8ecaff; border:1px solid #1e4976; }
.sev-info { background:#182430; color:#9fb2c4; border:1px solid #2a3a4a; }
.sev-good { background:#0d2a1b; color:#7ee2ac; border:1px solid #1c5b3a; }
.chips { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }
.chip { border:1px solid #1d2937; border-radius:999px; padding:4px 12px; font-size:11.5px;
  color:#9fb2c4; background:#101a24; }
.risk { font-size:32px; font-weight:700; line-height:1; color:TORECOLOR; }
.finding { border:1px solid #1d2937; border-left:4px solid #2a3a4a; border-radius:8px;
  padding:12px 14px; margin:10px 0; background:#0d161f; }
.finding.critical,.finding.high { border-left-color:#ef4444; }
.finding.medium { border-left-color:#eab308; }
.finding.low { border-left-color:#38bdf8; }
.finding.good { border-left-color:#22c55e; }
.finding .t { font-weight:600; color:#e9f3fc; margin-bottom:3px; }
.finding .d { color:#9fb2c4; font-size:12.5px; }
.finding .r { color:#7ee2ac; font-size:12px; margin-top:6px; }
footer { margin-top:44px; padding-top:14px; border-top:1px solid #1d2937;
  color:#6b7c8d; font-size:11.5px; }
@media print { body { background:#fff; color:#111; } .card,table,pre { background:#fff; }
  h1,h2,h3,.finding .t { color:#111; } }
</style></head><body><div class="wrap">""".replace("TORECOLOR", tone),
            "<header>",
            f"  <h1>{esc(self.title)}</h1>",
            "  <div class=\"sub\">target <b>%s</b> &middot; %s %s &middot; %s</div>" % (
                esc(meta["target"] or "-"), esc(meta["tool"]), esc(meta["version"]),
                esc(meta["finished"])),
            "</header>",
            '<div class="grid">',
            f'  <div class="card"><div class="k">Risk score</div>'
            f'<div class="risk">{score}<span class="sub">/100</span></div></div>',
        ]
        for label, key in (("Critical", "critical"), ("High", "high"),
                           ("Medium", "medium"), ("Low", "low")):
            parts.append(
                f'  <div class="card"><div class="k">{label}</div>'
                f'<div class="v">{counts.get(key, 0)}</div></div>'
            )
        parts += [
            "</div>",
            '<div class="chips">',
            f'  <span class="chip">module {esc(meta["module"] or "-")}</span>',
            f'  <span class="chip">host {esc(meta["host"] or "-")}</span>',
            f'  <span class="chip">elevated {meta["elevated"]}</span>',
            f'  <span class="chip">started {esc(meta["started"])}</span>',
            "</div>",
        ]

        if meta["command"]:
            parts.append(f"<h2>Command</h2><pre>{esc(meta['command'])}</pre>")

        for block in self.blocks:
            parts.append(f"<h2>{esc(block['title'])}</h2>")
            kind = block["type"]
            if kind == "kv":
                rows = "".join(
                    f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
                    for k, v in block["pairs"]
                )
                parts.append(f'<table class="kv"><tbody>{rows}</tbody></table>')
            elif kind == "text":
                parts.append(f"<pre>{esc(block['body'])}</pre>")
            elif kind == "table":
                head = "".join(f"<th>{esc(h)}</th>" for h in block["headers"])
                body = "".join(
                    "<tr>" + "".join(f"<td>{esc(str(cell))}</td>" for cell in row) + "</tr>"
                    for row in block["rows"]
                )
                parts.append(
                    f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
                )
                if block["note"]:
                    parts.append(f'<p class="note">{esc(block["note"])}</p>')
            elif kind == "findings":
                for row in block["rows"]:
                    severity = str(row.get("severity", "info")).lower()
                    remediation = (
                        f'<div class="r">&rarr; {esc(str(row["remediation"]))}</div>'
                        if row.get("remediation") else ""
                    )
                    parts.append(
                        f'<div class="finding {esc(severity)}">'
                        f'<div class="t"><span class="sev sev-{esc(severity)}">'
                        f'{esc(severity)}</span> {esc(str(row.get("title", "")))}</div>'
                        f'<div class="d">{esc(str(row.get("detail", "")))}</div>'
                        f"{remediation}</div>"
                    )

        parts.append(
            f'<footer>Generated by KMAX &middot; authorised testing only &middot; '
            f'{esc(meta["finished"])}</footer></div></body></html>'
        )
        return "".join(parts)

    # ------------------------------------------------------------------ #
    # Output
    # ------------------------------------------------------------------ #
    def render(self, fmt: str) -> str:
        fmt = (fmt or "html").lower()
        if fmt == "json":
            return self.to_json()
        if fmt in ("md", "markdown"):
            return self.to_markdown()
        if fmt in ("html", "htm"):
            return self.to_html()
        if fmt == "csv":
            return self.to_csv()
        raise ValueError(f"unsupported report format: {fmt}")

    def save(self, path: str, fmt: str | None = None) -> str:
        """Write the report; the extension decides the format when unset."""
        chosen = (fmt or format_for_path(path)).lower()
        if chosen == "md":
            chosen = "markdown"
        extension = os.path.splitext(path)[1]
        if not extension:
            path = path + FORMAT_EXTENSIONS.get(chosen, ".html")
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        payload = self.render(chosen)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(payload)
        return os.path.abspath(path)

    def print_summary(self) -> None:
        from . import ui

        counts = self.severity_counts()
        score = self.risk_score()
        style = "bgreen" if score < 15 else "byellow" if score < 45 else "bred"
        ui.plain()
        ui.kv([
            ("Sections", len(self.blocks)),
            ("Findings", sum(counts.values())),
            ("Risk score", ui.c(f"{score}/100", style, "bold")),
            ("Critical / High", f"{counts.get('critical', 0)} / {counts.get('high', 0)}"),
            ("Medium / Low", f"{counts.get('medium', 0)} / {counts.get('low', 0)}"),
        ])
