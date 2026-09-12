"""Deterministic, escaped reports. Output is private and never overwritten."""

import html
import os
import re
import tempfile
from pathlib import Path

from .common import STATUSES


def markdown_text(value):
    # Escape HTML and Markdown syntax supplied by host state or client names.
    value = html.escape(str(value), quote=True)
    value = value.replace("\\", "\\\\")
    for char in "`*_{}[]()#+-.!|":
        value = value.replace(char, "\\" + char)
    return value.replace("\r", " ").replace("\n", "<br>")


def render(findings, client, target, elevated):
    findings = sorted(findings, key=lambda f: (f.Section, f.Name, f.Detail))
    title = "Fieldkit Linux diagnostic report - " + client
    summary = ", ".join(
        f"{sum(f.Status == status for f in findings)} {status}" for status in STATUSES
    )
    meta = "Host: {}; root: {}".format(target, "yes" if elevated else "no")
    scope = "Preview: management, hardening, persistence, audit, DLP and identity review; socket bindings included; findings are scoped observations, not a complete security audit."
    md = [
        "# " + markdown_text(title),
        "",
        markdown_text(meta),
        "",
        markdown_text(scope),
        "",
        summary,
        "",
    ]
    rows = []
    previous = None
    for finding in findings:
        if previous != finding.Section:
            previous = finding.Section
            md.extend(
                [
                    "",
                    "## " + markdown_text(previous),
                    "",
                    "| Status | Check | Detail |",
                    "|---|---|---|",
                ]
            )
            rows.append('<tr><th colspan="3">' + html.escape(previous) + "</th></tr>")
        detail = markdown_text(finding.Detail)
        html_detail = html.escape(finding.Detail)
        if finding.Status in ("FAIL", "WARN") and finding.Remediation:
            detail += "<br>Remediation: " + markdown_text(finding.Remediation)
            html_detail += "<br><strong>Remediation:</strong> " + html.escape(
                finding.Remediation
            )
        md.append(f"| {finding.Status} | {markdown_text(finding.Name)} | {detail} |")
        rows.append(
            f'<tr><td class="{finding.Status.lower()}">{finding.Status}</td><td>{html.escape(finding.Name)}</td><td>{html_detail}</td></tr>'
        )
    document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:75rem;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #bbb;padding:.6rem;text-align:left}}
td{{vertical-align:top;overflow-wrap:anywhere}}th{{background:#eee}}
.fail{{color:#a00}}.warn{{color:#854600}}.pass{{color:#176126}}
</style></head><body><h1>{title}</h1><p>{meta}</p><p>{scope}</p><p>{summary}</p>
<table><caption>Findings</caption>{rows}</table>
<p>Read-only collection; only report files are written by Fieldkit.</p></body></html>
""".format(
        title=html.escape(title),
        meta=html.escape(meta),
        scope=html.escape(scope),
        summary=html.escape(summary),
        rows="\n".join(rows),
    )
    return "\n".join(md) + "\n", document


def export(findings, client, target, elevated, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # A new private directory prevents clobbering old reports or following
    # pre-planted file symlinks. Random filenames do not enter report contents.
    slug = re.sub(r"[^A-Za-z0-9_-]", "_", target)[:64] or "host"
    destination = Path(tempfile.mkdtemp(prefix=slug + "-linux-", dir=str(directory)))
    contents = render(findings, client, target, elevated)
    paths = []
    for suffix, content in zip(("md", "html"), contents):
        path = destination / ("report." + suffix)
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        paths.append(path)
    return paths
