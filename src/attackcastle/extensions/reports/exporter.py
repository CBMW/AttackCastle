from __future__ import annotations

import io
import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape, unescape

from attackcastle.extensions.reports.models import ReportExportResult, ReportTemplateSection


class ReportExportError(RuntimeError):
    """Raised when a Reports DOCX export cannot be completed."""


class ReportMergeToolUnavailableError(ReportExportError):
    """Raised when no supported DOCX merge backend can be found."""


class ReportConversionUnavailableError(ReportExportError):
    """Raised when a report cannot be converted into the requested format."""


DEFAULT_SECTIONS = [
    ReportTemplateSection(section_id="cover_page", template_filename="cover_page.docx"),
    ReportTemplateSection(section_id="chapter2", template_filename="chapter2.docx"),
    ReportTemplateSection(section_id="chapter1_1", template_filename="chapter1-1.docx"),
]

_WINDOWS_RESERVED_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')
_CONTENT_TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
_RELATIONSHIPS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_OFFICE_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_CHART_NS = "http://schemas.openxmlformats.org/drawingml/2006/chart"
_SPREADSHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_AFCHUNK_REL_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk"
_DOCX_CHUNK_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
_LIBREOFFICE_ENV_VARS = (
    "ATTACKCASTLE_REPORTS_MERGE_TOOL",
    "ATTACKCASTLE_LIBREOFFICE_PATH",
    "LIBREOFFICE_PATH",
    "SOFFICE_PATH",
)
_LIBREOFFICE_COMMANDS = ("soffice", "libreoffice", "lowriter")
_WORD_VIEW_RESTORE_PS = r"""
function Save-AttackCastleWordWindowViews {
    param([object]$WordApp)
    $states = @()
    if ($WordApp -eq $null) {
        return $states
    }
    for ($windowIndex = 1; $windowIndex -le $WordApp.Windows.Count; $windowIndex++) {
        try {
            $window = $WordApp.Windows.Item($windowIndex)
            $documentFullName = $window.Document.FullName
            $states += [PSCustomObject]@{
                FullName = $documentFullName
                ViewType = $window.View.Type
                SeekView = $window.View.SeekView
                ShowAll = $window.View.ShowAll
                ShowHiddenText = $window.View.ShowHiddenText
            }
        }
        catch {
        }
    }
    return $states
}

function Restore-AttackCastleWordWindowViews {
    param(
        [object]$WordApp,
        [object[]]$States
    )
    if ($WordApp -eq $null -or $States -eq $null) {
        return
    }
    foreach ($state in $States) {
        for ($windowIndex = 1; $windowIndex -le $WordApp.Windows.Count; $windowIndex++) {
            try {
                $window = $WordApp.Windows.Item($windowIndex)
                if ($window.Document.FullName -eq $state.FullName) {
                    $window.View.SeekView = $state.SeekView
                    $window.View.Type = $state.ViewType
                    $window.View.ShowAll = $state.ShowAll
                    $window.View.ShowHiddenText = $state.ShowHiddenText
                }
            }
            catch {
            }
        }
    }
}
"""
ET.register_namespace("", _CONTENT_TYPES_NS)
ET.register_namespace("", _RELATIONSHIPS_NS)
ET.register_namespace("w", _WORD_NS)
ET.register_namespace("c", _CHART_NS)


def templates_dir() -> Path:
    return Path(__file__).resolve().parent / "templates"


def sanitize_filename_part(value: str, fallback: str) -> str:
    cleaned = _WINDOWS_RESERVED_CHARS.sub("_", str(value or "").strip())
    cleaned = re.sub(r"\s+", "_", cleaned).strip("._ ")
    cleaned = re.sub(r"_+", "_", cleaned)
    return cleaned or fallback


def resolve_output_path(path_value: str, *, workspace_home: str = "", client_name: str = "", report_title: str = "", report_date: str = "") -> Path:
    raw = str(path_value or "").strip()
    if not raw:
        raise ReportExportError("Export path is required.")
    path = Path(raw).expanduser()
    if not path.is_absolute() and workspace_home:
        path = Path(workspace_home).expanduser() / path
    if path.suffix.lower() != ".docx":
        if raw.endswith(("/", "\\")) or not path.suffix:
            date_token = "".join(part for part in report_date.split("/") if part) or "report"
            filename = "_".join(
                [
                    sanitize_filename_part(client_name, "client"),
                    sanitize_filename_part(report_title, "report"),
                    date_token,
                ]
            )
            path = path / f"{filename}.docx"
        else:
            path = path.with_suffix(".docx")
    return path.resolve()


def _replace_shortcodes_in_xml(xml_text: str, replacements: dict[str, str]) -> str:
    if not replacements:
        return xml_text

    text_pattern = re.compile(r"(<w:t(?:\s[^>]*)?>)(.*?)(</w:t>)", flags=re.DOTALL)

    def replacement_ranges(combined_text: str) -> list[tuple[int, int, str]]:
        ranges: list[tuple[int, int, str]] = []
        for shortcode, value in replacements.items():
            start = 0
            while True:
                index = combined_text.find(shortcode, start)
                if index < 0:
                    break
                ranges.append((index, index + len(shortcode), str(value)))
                start = index + len(shortcode)
        ranges.sort(key=lambda item: item[0])
        return ranges

    def replace_paragraph(match: re.Match[str]) -> str:
        paragraph = match.group(0)
        text_nodes: list[dict[str, Any]] = []
        combined_parts: list[str] = []
        cursor = 0
        for text_match in text_pattern.finditer(paragraph):
            text = unescape(text_match.group(2))
            text_nodes.append(
                {
                    "xml_start": text_match.start(2),
                    "xml_end": text_match.end(2),
                    "text_start": cursor,
                    "text_end": cursor + len(text),
                    "text": text,
                }
            )
            combined_parts.append(text)
            cursor += len(text)
        if not text_nodes:
            return paragraph

        ranges = replacement_ranges("".join(combined_parts))
        if not ranges:
            return paragraph

        def rewritten_node_text(node: dict[str, Any]) -> str:
            node_start = int(node["text_start"])
            node_end = int(node["text_end"])
            text = str(node["text"])
            pos = node_start
            pieces: list[str] = []
            while pos < node_end:
                active = next((item for item in ranges if item[0] <= pos < item[1]), None)
                if active is not None:
                    if pos == active[0]:
                        pieces.append(escape(active[2]))
                    pos = min(active[1], node_end)
                    continue
                pieces.append(escape(text[pos - node_start]))
                pos += 1
            return "".join(pieces)

        rewritten = paragraph
        for node in reversed(text_nodes):
            rewritten = rewritten[: node["xml_start"]] + rewritten_node_text(node) + rewritten[node["xml_end"] :]
        return rewritten

    return re.sub(r"<w:p\b.*?</w:p>", replace_paragraph, xml_text, flags=re.DOTALL)


SEVERITY_CHART_ORDER = ("critical", "high", "medium", "low", "informational")


def _render_docx_template_bytes(
    template_path: Path,
    replacements: dict[str, str],
    severity_counts: dict[str, int] | None = None,
) -> dict[str, bytes]:
    if not template_path.exists():
        raise ReportExportError(f"Template not found: {template_path}")
    rendered: dict[str, bytes] = {}
    with zipfile.ZipFile(template_path, "r") as source:
        for item in source.infolist():
            data = source.read(item.filename)
            if item.filename.startswith("word/") and item.filename.endswith(".xml"):
                text = data.decode("utf-8")
                data = _replace_shortcodes_in_xml(text, replacements).encode("utf-8")
            rendered[item.filename] = data
    if severity_counts is not None:
        _update_docx_severity_chart(rendered, severity_counts)
    return rendered


def _docx_file_parts(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path, "r") as source:
        return {item.filename: source.read(item.filename) for item in source.infolist()}


def _pack_docx_bytes(parts: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as target:
        for name, data in parts.items():
            target.writestr(name, data)
    return stream.getvalue()


def _write_docx(parts: dict[str, bytes], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="attackcastle_reports_") as temp_dir:
        temp_path = Path(temp_dir) / output_path.name
        with zipfile.ZipFile(temp_path, "w", zipfile.ZIP_DEFLATED) as target:
            for name, data in parts.items():
                target.writestr(name, data)
        shutil.move(str(temp_path), str(output_path))


def _render_docx_template(template_path: Path, output_path: Path, replacements: dict[str, str]) -> None:
    _write_docx(_render_docx_template_bytes(template_path, replacements), output_path)


def _render_docx_template_file(
    template_path: Path,
    output_path: Path,
    replacements: dict[str, str],
    severity_counts: dict[str, int] | None = None,
) -> None:
    _write_docx(_render_docx_template_bytes(template_path, replacements, severity_counts), output_path)


def _normalize_finding_severity(row: dict[str, Any]) -> str:
    value = str(row.get("effective_severity") or row.get("severity_override") or row.get("severity") or "").strip().lower()
    aliases = {
        "crit": "critical",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "low": "low",
        "info": "informational",
        "informational": "informational",
        "information": "informational",
    }
    return aliases.get(value, "informational")


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_CHART_ORDER}
    for row in findings:
        if isinstance(row, dict):
            counts[_normalize_finding_severity(row)] += 1
    return counts


def _overall_exposure(counts: dict[str, int]) -> str:
    for severity in SEVERITY_CHART_ORDER:
        if counts.get(severity, 0) > 0:
            return "Informational" if severity == "informational" else severity.title()
    return "Informational"


def _severity_chart_values(counts: dict[str, int]) -> list[int | None]:
    values: list[int | None] = []
    for severity in SEVERITY_CHART_ORDER:
        value = int(counts.get(severity, 0))
        values.append(value if value > 0 else None)
    return values


def build_shortcode_values(
    *,
    report_title: str,
    report_type: str,
    client_name: str,
    report_date: str,
    included_findings: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
    selected_findings = list(included_findings or [])
    counts = _severity_counts(selected_findings)
    return {
        "%%report_title%%": str(report_title or ""),
        "%%report_type%%": str(report_type or ""),
        "%%client_name%%": str(client_name or ""),
        "%%report_date%%": str(report_date or ""),
        "%%vulnerability_counts1%%": str(sum(counts.values())),
        "%%overall_exposure%%": _overall_exposure(counts),
    }


def _docx_text_from_parts(parts: dict[str, bytes]) -> str:
    document_xml = _read_text_part(parts, "word/document.xml")
    body_xml = _body_inner_xml(document_xml)
    paragraphs: list[str] = []
    for paragraph_match in re.finditer(r"<w:p\b.*?</w:p>", body_xml, flags=re.DOTALL):
        paragraph = paragraph_match.group(0)
        text_parts = [
            unescape(text_match.group(1))
            for text_match in re.finditer(r"<w:t(?:\s[^>]*)?>(.*?)</w:t>", paragraph, flags=re.DOTALL)
        ]
        if not text_parts and "<w:br" not in paragraph:
            continue
        text = "".join(text_parts).strip()
        if text:
            paragraphs.append(text)
        elif paragraphs and paragraphs[-1]:
            paragraphs.append("")
    return "\n\n".join(paragraphs).strip()


def render_section_preview_text(
    section: ReportTemplateSection,
    shortcode_values: dict[str, str],
    *,
    included_findings: list[dict[str, Any]] | None = None,
) -> str:
    selected_findings = list(included_findings or [])
    template_path = _template_path_for_section(section)
    parts = _render_docx_template_bytes(template_path, shortcode_values, _severity_counts(selected_findings))
    text = _docx_text_from_parts(parts)
    return text or "This section rendered successfully, but no text content was found in the template."


def render_section_docx(
    section: ReportTemplateSection,
    output_path: Path,
    shortcode_values: dict[str, str],
    *,
    included_findings: list[dict[str, Any]] | None = None,
) -> Path:
    selected_findings = list(included_findings or [])
    template_path = _template_path_for_section(section)
    _render_docx_template_file(
        template_path,
        output_path,
        shortcode_values,
        _severity_counts(selected_findings),
    )
    return output_path.resolve()


def render_section_preview_html(
    section: ReportTemplateSection,
    shortcode_values: dict[str, str],
    *,
    included_findings: list[dict[str, Any]] | None = None,
    asset_dir: Path | None = None,
    merge_tool_path: str = "",
) -> str:
    selected_findings = list(included_findings or [])
    template_path = _template_path_for_section(section)
    parts = _render_docx_template_bytes(template_path, shortcode_values, _severity_counts(selected_findings))
    converted_html = _docx_parts_to_converted_preview_html(parts, asset_dir=asset_dir, merge_tool_path=merge_tool_path)
    if converted_html:
        return converted_html
    return _docx_parts_to_preview_html(parts, asset_dir=asset_dir)


def _docx_parts_to_converted_preview_html(
    parts: dict[str, bytes],
    *,
    asset_dir: Path | None,
    merge_tool_path: str = "",
) -> str:
    if asset_dir is None:
        return ""
    shutil.rmtree(asset_dir, ignore_errors=True)
    asset_dir.mkdir(parents=True, exist_ok=True)
    source_path = asset_dir / "preview.docx"
    html_path = asset_dir / "preview.html"
    _write_docx(parts, source_path)

    errors: list[str] = []
    if merge_tool_path:
        try:
            return _read_converted_preview_html(
                _convert_docx_to_html_with_libreoffice(source_path, asset_dir, merge_tool_path),
            )
        except ReportExportError as exc:
            errors.append(str(exc))
    if os.name == "nt" and not os.environ.get("ATTACKCASTLE_REPORTS_DISABLE_WORD_AUTOMATION"):
        try:
            return _read_converted_preview_html(_convert_docx_to_html_with_word(source_path, html_path))
        except ReportExportError as exc:
            errors.append(str(exc))
    if not merge_tool_path:
        try:
            return _read_converted_preview_html(
                _convert_docx_to_html_with_libreoffice(source_path, asset_dir, merge_tool_path),
            )
        except ReportExportError as exc:
            errors.append(str(exc))
    return ""


def _read_converted_preview_html(html_path: Path) -> str:
    raw = html_path.read_bytes()
    try:
        html_text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        html_text = raw.decode("cp1252", errors="replace")
    html_text = _rewrite_preview_html_asset_urls(html_text, html_path.parent)
    base_href = html.escape(html_path.parent.resolve().as_uri() + "/")
    if "<head" in html_text.lower():
        return re.sub(r"(<head\b[^>]*>)", rf'\1<base href="{base_href}">', html_text, count=1, flags=re.IGNORECASE)
    return f'<html><head><base href="{base_href}"></head><body>{html_text}</body></html>'


def _rewrite_preview_html_asset_urls(html_text: str, base_dir: Path) -> str:
    def rewrite_attr(match: re.Match[str]) -> str:
        attr = match.group("attr")
        quote = match.group("quote")
        value = html.unescape(match.group("value"))
        lowered = value.lower()
        if (
            not value
            or lowered.startswith(("http:", "https:", "file:", "data:", "mailto:"))
            or value.startswith("#")
        ):
            return match.group(0)
        target = (base_dir / value).resolve()
        return f'{attr}={quote}{html.escape(target.as_uri())}{quote}'

    return re.sub(
        r'(?P<attr>\b(?:src|href))=(?P<quote>["\'])(?P<value>.*?)(?P=quote)',
        rewrite_attr,
        html_text,
        flags=re.IGNORECASE,
    )


def _convert_docx_to_html_with_word(source_path: Path, output_html: Path) -> Path:
    source_path = source_path.resolve()
    output_html = output_html.resolve()
    output_html.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="attackcastle_word_html_") as temp_dir:
        script_path = Path(temp_dir) / "convert-docx-html.ps1"
        source_json = json.dumps(str(source_path))
        output_json = json.dumps(str(output_html))
        script_path.write_text(
            f"""
$ErrorActionPreference = 'Stop'
$sourcePath = @'
{source_json}
'@ | ConvertFrom-Json
$outputPath = @'
{output_json}
'@ | ConvertFrom-Json
$word = $null
$doc = $null
$shouldQuitWord = $true
$attackCastleWindowViews = @()
{_WORD_VIEW_RESTORE_PS}
try {{
    if (Test-Path -LiteralPath $outputPath) {{
        Remove-Item -LiteralPath $outputPath -Force
    }}
    $word = New-Object -ComObject Word.Application
    $shouldQuitWord = ($word.Documents.Count -eq 0)
    $attackCastleWindowViews = Save-AttackCastleWordWindowViews $word
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $doc = $word.Documents.Open([string]$sourcePath, $false, $true, $false)
    $doc.SaveAs2([string]$outputPath, 10)
}}
finally {{
    if ($doc -ne $null) {{
        $doc.Close($false)
    }}
    if ($word -ne $null) {{
        Restore-AttackCastleWordWindowViews $word $attackCastleWindowViews
        if ($shouldQuitWord) {{
            $word.Quit()
        }}
    }}
    if ($doc -ne $null) {{
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($doc) | Out-Null
    }}
    if ($word -ne $null) {{
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
    }}
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}}
""",
            encoding="utf-8",
        )
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script_path),
                ],
                capture_output=True,
                text=True,
                timeout=90,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReportExportError(f"Microsoft Word preview conversion could not run: {exc}") from exc
    if result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        raise ReportExportError(f"Microsoft Word failed to render preview HTML: {details}")
    if not output_html.exists():
        raise ReportExportError("Microsoft Word did not create preview HTML.")
    return output_html


def _convert_docx_to_html_with_libreoffice(source_path: Path, output_dir: Path, binary_path: str = "") -> Path:
    soffice = _find_libreoffice_binary(binary_path)
    if not soffice:
        raise ReportMergeToolUnavailableError("LibreOffice is not available for report preview rendering.")
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            [
                soffice,
                "--headless",
                "--nologo",
                "--nofirststartwizard",
                "--convert-to",
                "html",
                "--outdir",
                str(output_dir),
                str(source_path),
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReportExportError(f"LibreOffice preview conversion could not run: {exc}") from exc
    output_html = output_dir / f"{source_path.stem}.html"
    if result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        raise ReportExportError(f"LibreOffice failed to render preview HTML: {details}")
    if not output_html.exists():
        raise ReportExportError("LibreOffice did not create preview HTML.")
    return output_html


def _docx_parts_to_preview_html(parts: dict[str, bytes], *, asset_dir: Path | None = None) -> str:
    document_xml = _read_text_part(parts, "word/document.xml")
    root = ET.fromstring(document_xml)
    rels = _docx_relationship_targets(parts, "word/_rels/document.xml.rels")
    body = root.find(f".//{{{_WORD_NS}}}body")
    if body is None:
        raise ReportExportError("Template document.xml does not contain a Word body.")
    page_background = _preview_page_background(document_xml)
    page_color = "#ffffff" if page_background.lower() not in {"#ffffff", "white"} else "#111827"
    body_background = page_background if page_background.lower() not in {"#ffffff", "white"} else "#eef1f5"
    page_style = (
        "box-sizing:border-box;"
        "width:794px;"
        "min-height:1123px;"
        "margin:18px auto;"
        "padding:72px;"
        f"background-color:{page_background};"
        f"color:{page_color};"
        "font-family:Arial, sans-serif;"
        "overflow:hidden;"
    )
    body_html = "".join(_preview_block_html(child, parts, rels, asset_dir) for child in body)
    return (
        "<html><head><meta charset=\"utf-8\">"
        "<style>"
        f"body{{margin:0;background-color:{body_background};color:{page_color};font-family:Arial, sans-serif;}}"
        "p{margin:0 0 10px 0;line-height:1.25;min-height:1em;}"
        "img{max-width:100%;height:auto;vertical-align:middle;}"
        "table{border-collapse:collapse;width:100%;margin:8px 0;}"
        "td{border:1px solid #d1d5db;padding:6px;vertical-align:top;}"
        "</style></head>"
        f"<body bgcolor=\"{html.escape(body_background)}\" text=\"{html.escape(page_color)}\">"
        f"<div style=\"{page_style}\">"
        f"{body_html or '<p></p>'}"
        "</div></body></html>"
    )


def _preview_page_background(document_xml: str) -> str:
    background_match = re.search(r"<w:background\b[^>]*\bw:color=\"([^\"]+)\"", document_xml)
    if background_match is not None:
        return _preview_color_value(background_match.group(1), "#ffffff")
    rect_match = re.search(r"<v:rect\b[^>]*\bfillcolor=\"([^\"]+)\"", document_xml)
    if rect_match is not None:
        return _preview_color_value(rect_match.group(1), "#ffffff")
    fill_match = re.search(r"<v:fill\b[^>]*\bcolor=\"([^\"]+)\"", document_xml)
    if fill_match is not None:
        return _preview_color_value(fill_match.group(1), "#ffffff")
    return "#ffffff"


def _preview_color_value(value: str, fallback: str = "#111827") -> str:
    token = str(value or "").strip().split()[0].strip()
    if not token:
        return fallback
    named = {
        "black": "#000000",
        "white": "#ffffff",
        "red": "#ff0000",
        "green": "#008000",
        "blue": "#0000ff",
        "yellow": "#ffff00",
        "gray": "#808080",
        "grey": "#808080",
    }
    lowered = token.lower()
    if lowered in named:
        return named[lowered]
    if re.fullmatch(r"[0-9A-Fa-f]{6}", token):
        return f"#{token}"
    if re.fullmatch(r"#[0-9A-Fa-f]{6}", token):
        return token
    return fallback


def _docx_relationship_targets(parts: dict[str, bytes], rels_name: str) -> dict[str, str]:
    raw = parts.get(rels_name)
    if raw is None:
        return {}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {}
    targets: dict[str, str] = {}
    for relationship in root:
        rel_id = str(relationship.attrib.get("Id", ""))
        target = str(relationship.attrib.get("Target", ""))
        if rel_id and target:
            targets[rel_id] = _relationship_target_part("word/document.xml", target)
    return targets


def _preview_block_html(
    element: ET.Element,
    parts: dict[str, bytes],
    rels: dict[str, str],
    asset_dir: Path | None,
) -> str:
    if element.tag == f"{{{_WORD_NS}}}p":
        return _preview_paragraph_html(element, parts, rels, asset_dir)
    if element.tag == f"{{{_WORD_NS}}}tbl":
        return _preview_table_html(element, parts, rels, asset_dir)
    return ""


def _preview_table_html(
    table: ET.Element,
    parts: dict[str, bytes],
    rels: dict[str, str],
    asset_dir: Path | None,
) -> str:
    rows: list[str] = []
    for row in table.findall(f"{{{_WORD_NS}}}tr"):
        cells: list[str] = []
        for cell in row.findall(f"{{{_WORD_NS}}}tc"):
            content = "".join(_preview_block_html(child, parts, rels, asset_dir) for child in cell)
            cells.append(f"<td>{content}</td>")
        if cells:
            rows.append(f"<tr>{''.join(cells)}</tr>")
    return f"<table>{''.join(rows)}</table>" if rows else ""


def _preview_paragraph_html(
    paragraph: ET.Element,
    parts: dict[str, bytes],
    rels: dict[str, str],
    asset_dir: Path | None,
) -> str:
    runs = [
        _preview_run_html(run, parts, rels, asset_dir)
        for run in paragraph.findall(f"{{{_WORD_NS}}}r")
    ]
    style = _preview_paragraph_style(paragraph)
    content = "".join(runs).strip()
    if not content:
        content = "&nbsp;"
    return f"<p style=\"{style}\">{content}</p>"


def _preview_paragraph_style(paragraph: ET.Element) -> str:
    styles = []
    jc = paragraph.find(f".//{{{_WORD_NS}}}jc")
    if jc is not None:
        value = jc.attrib.get(f"{{{_WORD_NS}}}val", "")
        if value in {"center", "right", "both"}:
            styles.append(f"text-align:{'justify' if value == 'both' else value}")
    return ";".join(styles)


def _preview_run_html(
    run: ET.Element,
    parts: dict[str, bytes],
    rels: dict[str, str],
    asset_dir: Path | None,
) -> str:
    pieces: list[str] = []
    for child in run:
        if child.tag == f"{{{_WORD_NS}}}t":
            pieces.append(html.escape(child.text or ""))
        elif child.tag == f"{{{_WORD_NS}}}tab":
            pieces.append("&nbsp;&nbsp;&nbsp;&nbsp;")
        elif child.tag == f"{{{_WORD_NS}}}br":
            pieces.append("<br>")
        elif child.tag in {f"{{{_WORD_NS}}}drawing", f"{{{_WORD_NS}}}pict"}:
            pieces.extend(_preview_images_html(child, parts, rels, asset_dir))
    content = "".join(pieces)
    if not content:
        return ""
    style = _preview_run_style(run)
    return f"<span style=\"{style}\">{content}</span>" if style else content


def _preview_run_style(run: ET.Element) -> str:
    rpr = run.find(f"{{{_WORD_NS}}}rPr")
    if rpr is None:
        return ""
    styles: list[str] = []
    if rpr.find(f"{{{_WORD_NS}}}b") is not None:
        styles.append("font-weight:700")
    if rpr.find(f"{{{_WORD_NS}}}i") is not None:
        styles.append("font-style:italic")
    if rpr.find(f"{{{_WORD_NS}}}u") is not None:
        styles.append("text-decoration:underline")
    color = rpr.find(f"{{{_WORD_NS}}}color")
    if color is not None:
        value = str(color.attrib.get(f"{{{_WORD_NS}}}val", "")).strip()
        if value and value.lower() != "auto":
            styles.append(f"color:#{html.escape(value)}")
    size = rpr.find(f"{{{_WORD_NS}}}sz")
    if size is not None:
        try:
            half_points = int(size.attrib.get(f"{{{_WORD_NS}}}val", "0"))
            if half_points > 0:
                styles.append(f"font-size:{half_points / 2:.1f}pt")
        except ValueError:
            pass
    fonts = rpr.find(f"{{{_WORD_NS}}}rFonts")
    if fonts is not None:
        family = (
            fonts.attrib.get(f"{{{_WORD_NS}}}ascii")
            or fonts.attrib.get(f"{{{_WORD_NS}}}hAnsi")
            or ""
        )
        if family:
            styles.append(f"font-family:{html.escape(family)}, Arial, sans-serif")
    return ";".join(styles)


def _preview_images_html(
    element: ET.Element,
    parts: dict[str, bytes],
    rels: dict[str, str],
    asset_dir: Path | None,
) -> list[str]:
    if _preview_drawing_is_visually_off_page(element):
        return []
    result: list[str] = []
    embed_key = f"{{{_OFFICE_REL_NS}}}embed"
    id_key = f"{{{_OFFICE_REL_NS}}}id"
    for candidate in element.iter():
        rel_id = candidate.attrib.get(embed_key) or candidate.attrib.get(id_key)
        if not rel_id:
            continue
        target = rels.get(str(rel_id), "")
        if not target or target not in parts:
            continue
        source = _preview_image_source(target, parts[target], asset_dir)
        if source:
            result.append(f'<img src="{html.escape(source)}">')
    return result


def _preview_drawing_is_visually_off_page(element: ET.Element) -> bool:
    anchor = element.find(".//{http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing}anchor")
    if anchor is None:
        return False
    if str(anchor.attrib.get("hidden", "")).lower() in {"1", "true"}:
        return True
    position_h = anchor.find("{http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing}positionH")
    position_v = anchor.find("{http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing}positionV")
    if position_h is None or position_v is None:
        return False
    if position_h.attrib.get("relativeFrom") != "page" or position_v.attrib.get("relativeFrom") != "page":
        return False
    try:
        offset_h = int((position_h.findtext("{http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing}posOffset") or "0").strip())
        offset_v = int((position_v.findtext("{http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing}posOffset") or "0").strip())
    except ValueError:
        return False
    return offset_h < 0 and offset_v < 0


def _preview_image_source(part_name: str, data: bytes, asset_dir: Path | None) -> str:
    if asset_dir is None:
        import base64

        suffix = Path(part_name).suffix.lower().lstrip(".") or "png"
        mime = "jpeg" if suffix in {"jpg", "jpeg"} else suffix
        encoded = base64.b64encode(data).decode("ascii")
        return f"data:image/{mime};base64,{encoded}"
    asset_dir.mkdir(parents=True, exist_ok=True)
    target = asset_dir / Path(part_name).name
    target.write_bytes(data)
    return target.resolve().as_uri()


def _update_docx_severity_chart(parts: dict[str, bytes], severity_counts: dict[str, int]) -> None:
    values = _severity_chart_values(severity_counts)
    for name, data in list(parts.items()):
        if name.startswith("word/charts/") and name.endswith(".xml"):
            parts[name] = _update_chart_severity_counts(data, values)
        elif name.startswith("word/embeddings/") and name.lower().endswith(".xlsx"):
            parts[name] = _update_embedded_chart_workbook(data, values)


def _update_chart_severity_counts(data: bytes, values: list[int | None]) -> bytes:
    try:
        xml_text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data

    point_values = [None if value is None else str(value) for value in values]
    changed = False

    def replace_num_ref(match: re.Match[str]) -> str:
        nonlocal changed
        block = match.group(0)
        if "$B$2:$B$6" not in block:
            return block
        cache_match = re.search(
            r"<(?P<prefix>[A-Za-z_][\w.-]*:)?numCache\b[^>]*>.*?</(?(prefix)(?P=prefix))numCache>",
            block,
            flags=re.DOTALL,
        )
        if cache_match is None:
            return block
        cache_prefix = cache_match.group("prefix") or ""
        cache_xml = cache_match.group(0)
        format_match = re.search(
            rf"<{re.escape(cache_prefix)}formatCode\b[^>]*>.*?</{re.escape(cache_prefix)}formatCode>",
            cache_xml,
            flags=re.DOTALL,
        )
        format_xml = format_match.group(0) if format_match is not None else f"<{cache_prefix}formatCode>General</{cache_prefix}formatCode>"
        points_xml = "".join(
            f'<{cache_prefix}pt idx="{index}"><{cache_prefix}v>{value}</{cache_prefix}v></{cache_prefix}pt>'
            for index, value in enumerate(point_values)
            if value is not None
        )
        replacement_cache = (
            f"<{cache_prefix}numCache>"
            f"{format_xml}"
            f'<{cache_prefix}ptCount val="{len(point_values)}"/>'
            f"{points_xml}"
            f"</{cache_prefix}numCache>"
        )
        changed = True
        return block[: cache_match.start()] + replacement_cache + block[cache_match.end() :]

    updated = re.sub(
        r"<(?P<prefix>[A-Za-z_][\w.-]*:)?numRef\b[^>]*>.*?</(?(prefix)(?P=prefix))numRef>",
        replace_num_ref,
        xml_text,
        flags=re.DOTALL,
    )
    return updated.encode("utf-8") if changed else data


def _update_embedded_chart_workbook(data: bytes, values: list[int | None]) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as source:
            workbook_parts = {item.filename: source.read(item.filename) for item in source.infolist()}
    except zipfile.BadZipFile:
        return data
    sheet_name = "xl/worksheets/sheet1.xml"
    if sheet_name not in workbook_parts:
        return data
    try:
        sheet_text = workbook_parts[sheet_name].decode("utf-8")
    except UnicodeDecodeError:
        return data

    changed = False

    def replace_cell_value(text: str, cell_ref: str, value: int | None) -> str:
        nonlocal changed
        cell_pattern = re.compile(
            rf"(<(?P<prefix>[A-Za-z_][\w.-]*:)?c\b(?=[^>]*\br=\"{re.escape(cell_ref)}\")[^>]*>)(?P<body>.*?)(</(?(prefix)(?P=prefix))c>)",
            flags=re.DOTALL,
        )

        def replace_cell(match: re.Match[str]) -> str:
            nonlocal changed
            body = match.group("body")
            value_pattern = re.compile(
                r"(<(?P<prefix>[A-Za-z_][\w.-]*:)?v\b[^>]*>).*?(</(?(prefix)(?P=prefix))v>)",
                flags=re.DOTALL,
            )
            if value is None:
                changed = True
                body = value_pattern.sub("", body, count=1)
                opening = re.sub(r'\s+t="[^"]*"', "", match.group(1), count=1)
                return f"{opening}{body}{match.group(4)}"
            if value_pattern.search(body):
                changed = True
                body = value_pattern.sub(lambda value_match: f"{value_match.group(1)}{value}{value_match.group(3)}", body, count=1)
            else:
                cell_prefix = match.group("prefix") or ""
                changed = True
                body = f"{body}<{cell_prefix}v>{value}</{cell_prefix}v>"
            opening = re.sub(r'\s+t="[^"]*"', "", match.group(1), count=1)
            return f"{opening}{body}{match.group(4)}"

        return cell_pattern.sub(replace_cell, text, count=1)

    for row_number, value in enumerate(values, start=2):
        sheet_text = replace_cell_value(sheet_text, f"B{row_number}", value)
    if not changed:
        return data
    workbook_parts[sheet_name] = sheet_text.encode("utf-8")
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as target:
        for name, payload in workbook_parts.items():
            target.writestr(name, payload)
    return stream.getvalue()


def _template_path_for_section(section: ReportTemplateSection) -> Path:
    path = templates_dir() / section.template_filename
    if path.exists():
        return path
    if section.template_filename == "chapter2.docx":
        fallback = templates_dir() / "chapter1.docx"
        if fallback.exists():
            return fallback
    return path


def _read_text_part(parts: dict[str, bytes], name: str) -> str:
    try:
        return parts[name].decode("utf-8")
    except KeyError as exc:
        raise ReportExportError(f"Required DOCX part missing: {name}") from exc


def _body_inner_xml(document_xml: str) -> str:
    match = re.search(r"<w:body\b[^>]*>(?P<body>.*)</w:body>", document_xml, flags=re.DOTALL)
    if match is None:
        raise ReportExportError("Template document.xml does not contain a Word body.")
    return match.group("body")


def _replace_body_inner_xml(document_xml: str, body_inner: str) -> str:
    return re.sub(
        r"(<w:body\b[^>]*>).*?(</w:body>)",
        lambda match: f"{match.group(1)}{body_inner}{match.group(2)}",
        document_xml,
        flags=re.DOTALL,
    )


def _split_final_section_properties(body_inner: str) -> tuple[str, str]:
    final_paragraph_match = re.search(
        r"(?P<p><w:p\b(?:(?!<w:p\b).)*?<w:sectPr\b.*?</w:sectPr>.*?</w:p>)\s*$",
        body_inner,
        flags=re.DOTALL,
    )
    if final_paragraph_match is not None:
        paragraph = final_paragraph_match.group("p")
        section_match = re.search(r"(?P<sect><w:sectPr\b.*?</w:sectPr>)", paragraph, flags=re.DOTALL)
        if section_match is not None:
            return body_inner[: final_paragraph_match.start("p")], section_match.group("sect")
    match = re.search(r"(?P<sect><w:sectPr\b.*?</w:sectPr>)\s*$", body_inner, flags=re.DOTALL)
    if match is None:
        return body_inner, ""
    return body_inner[: match.start("sect")], match.group("sect")


def _section_break_paragraph(section_properties: str) -> str:
    if not section_properties:
        return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'
    return f'<w:p><w:pPr>{section_properties}</w:pPr><w:r><w:br w:type="page"/></w:r></w:p>'


def _page_break_paragraph() -> str:
    return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'


def _relationship_root(parts: dict[str, bytes], rels_name: str) -> ET.Element:
    raw = parts.get(rels_name)
    if raw is None:
        return ET.Element(f"{{{_RELATIONSHIPS_NS}}}Relationships")
    return ET.fromstring(raw)


def _next_relationship_id(root: ET.Element) -> int:
    highest = 0
    for relationship in root:
        value = relationship.attrib.get("Id", "")
        if value.startswith("rId") and value[3:].isdigit():
            highest = max(highest, int(value[3:]))
    return highest + 1


def _relationship_target_part(source_part: str, target: str) -> str:
    if target.startswith("/"):
        return target.lstrip("/")
    base = Path(source_part).parent
    return str((base / target).as_posix())


def _unique_part_name(parts: dict[str, bytes], source_part: str, section_id: str) -> str:
    source = Path(source_part)
    parent = source.parent.as_posix()
    stem = source.stem
    suffix = source.suffix
    candidate = f"{parent}/attackcastle_{section_id}_{stem}{suffix}"
    counter = 2
    while candidate in parts:
        candidate = f"{parent}/attackcastle_{section_id}_{stem}_{counter}{suffix}"
        counter += 1
    return candidate


def _relative_target(from_part: str, target_part: str) -> str:
    from_parent = Path(from_part).parent
    target_path = Path(target_part)
    try:
        return target_path.relative_to(from_parent).as_posix()
    except ValueError:
        return target_path.as_posix()


def _content_type_map(parts: dict[str, bytes]) -> dict[str, str]:
    raw = parts.get("[Content_Types].xml")
    if raw is None:
        return {}
    root = ET.fromstring(raw)
    result: dict[str, str] = {}
    for override in root.findall(f"{{{_CONTENT_TYPES_NS}}}Override"):
        part_name = str(override.attrib.get("PartName", "")).lstrip("/")
        content_type = str(override.attrib.get("ContentType", ""))
        if part_name and content_type:
            result[part_name] = content_type
    return result


def _ensure_content_type_override(parts: dict[str, bytes], part_name: str, content_type: str) -> None:
    if not content_type:
        return
    raw = parts.get("[Content_Types].xml")
    if raw is None:
        return
    root = ET.fromstring(raw)
    normalized = "/" + part_name.lstrip("/")
    for override in root.findall(f"{{{_CONTENT_TYPES_NS}}}Override"):
        if override.attrib.get("PartName") == normalized:
            override.attrib["ContentType"] = content_type
            parts["[Content_Types].xml"] = ET.tostring(root, encoding="utf-8", xml_declaration=True)
            return
    ET.SubElement(root, f"{{{_CONTENT_TYPES_NS}}}Override", {"PartName": normalized, "ContentType": content_type})
    parts["[Content_Types].xml"] = ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _merge_document_relationships(
    base_parts: dict[str, bytes],
    chapter_parts: dict[str, bytes],
    chapter_document_xml: str,
    section_id: str,
) -> str:
    source_rels_name = "word/_rels/document.xml.rels"
    target_rels_name = "word/_rels/document.xml.rels"
    source_root = _relationship_root(chapter_parts, source_rels_name)
    target_root = _relationship_root(base_parts, target_rels_name)
    content_types = _content_type_map(chapter_parts)
    next_id = _next_relationship_id(target_root)
    relationship_id_map: dict[str, str] = {}
    referenced_ids = set(re.findall(r'r:(?:id|embed|link)="([^"]+)"', chapter_document_xml))

    for relationship in source_root:
        old_id = str(relationship.attrib.get("Id", ""))
        target = str(relationship.attrib.get("Target", ""))
        rel_type = str(relationship.attrib.get("Type", ""))
        if not old_id or not target or not rel_type:
            continue
        if old_id not in referenced_ids:
            continue
        new_attrib = dict(relationship.attrib)
        new_id = f"rId{next_id}"
        next_id += 1
        relationship_id_map[old_id] = new_id
        new_attrib["Id"] = new_id
        if relationship.attrib.get("TargetMode") != "External":
            source_part = _relationship_target_part("word/document.xml", target)
            if source_part in chapter_parts:
                copied_part = _unique_part_name(base_parts, source_part, section_id)
                base_parts[copied_part] = chapter_parts[source_part]
                _ensure_content_type_override(base_parts, copied_part, content_types.get(source_part, ""))
                new_attrib["Target"] = _relative_target("word/document.xml", copied_part)
        ET.SubElement(target_root, f"{{{_RELATIONSHIPS_NS}}}Relationship", new_attrib)

    base_parts[target_rels_name] = ET.tostring(target_root, encoding="utf-8", xml_declaration=True)
    for old_id, new_id in relationship_id_map.items():
        chapter_document_xml = re.sub(rf'(?P<attr>r:(?:id|embed|link))="{re.escape(old_id)}"', rf'\g<attr>="{new_id}"', chapter_document_xml)
    return chapter_document_xml


def _merge_styles(base_parts: dict[str, bytes], chapter_parts: dict[str, bytes]) -> None:
    if "word/styles.xml" not in base_parts or "word/styles.xml" not in chapter_parts:
        return
    try:
        base_root = ET.fromstring(base_parts["word/styles.xml"])
        chapter_root = ET.fromstring(chapter_parts["word/styles.xml"])
    except ET.ParseError:
        return
    style_tag = f"{{{_WORD_NS}}}style"
    style_id_key = f"{{{_WORD_NS}}}styleId"
    existing = {
        str(style.attrib.get(style_id_key, ""))
        for style in base_root.findall(style_tag)
        if style.attrib.get(style_id_key)
    }
    changed = False
    for style in chapter_root.findall(style_tag):
        style_id = str(style.attrib.get(style_id_key, ""))
        if not style_id or style_id in existing:
            continue
        base_root.append(style)
        existing.add(style_id)
        changed = True
    if changed:
        base_parts["word/styles.xml"] = ET.tostring(base_root, encoding="utf-8", xml_declaration=True)


def _merge_docx_sections(base_parts: dict[str, bytes], section_parts: list[tuple[str, dict[str, bytes]]]) -> dict[str, bytes]:
    base_document_xml = _read_text_part(base_parts, "word/document.xml")
    base_body, base_sect = _split_final_section_properties(_body_inner_xml(base_document_xml))
    merged_body = base_body
    final_sect = base_sect

    for section_id, chapter_parts in section_parts:
        _merge_styles(base_parts, chapter_parts)
        chapter_document_xml = _read_text_part(chapter_parts, "word/document.xml")
        chapter_document_xml = _merge_document_relationships(base_parts, chapter_parts, chapter_document_xml, section_id)
        chapter_body, chapter_sect = _split_final_section_properties(_body_inner_xml(chapter_document_xml))
        merged_body += _section_break_paragraph(final_sect) + chapter_body
        final_sect = chapter_sect or final_sect

    base_parts["word/document.xml"] = _replace_body_inner_xml(base_document_xml, merged_body + final_sect).encode("utf-8")
    return base_parts


def _append_docx_sections_as_alt_chunks(base_parts: dict[str, bytes], section_parts: list[tuple[str, dict[str, bytes]]]) -> dict[str, bytes]:
    base_document_xml = _read_text_part(base_parts, "word/document.xml")
    base_body, base_sect = _split_final_section_properties(_body_inner_xml(base_document_xml))
    target_rels_name = "word/_rels/document.xml.rels"
    target_root = _relationship_root(base_parts, target_rels_name)
    next_id = _next_relationship_id(target_root)
    appended_body = base_body

    for section_id, chapter_parts in section_parts:
        chunk_name = _unique_part_name(base_parts, f"word/{section_id}.docx", section_id)
        base_parts[chunk_name] = _pack_docx_bytes(chapter_parts)
        _ensure_content_type_override(base_parts, chunk_name, _DOCX_CHUNK_CONTENT_TYPE)
        rel_id = f"rId{next_id}"
        next_id += 1
        ET.SubElement(
            target_root,
            f"{{{_RELATIONSHIPS_NS}}}Relationship",
            {
                "Id": rel_id,
                "Type": _AFCHUNK_REL_TYPE,
                "Target": _relative_target("word/document.xml", chunk_name),
            },
        )
        appended_body += _page_break_paragraph() + f'<w:altChunk r:id="{rel_id}"/>'

    base_parts[target_rels_name] = ET.tostring(target_root, encoding="utf-8", xml_declaration=True)
    base_parts["word/document.xml"] = _replace_body_inner_xml(base_document_xml, appended_body + base_sect).encode("utf-8")
    return base_parts


def _merge_docx_files_with_word(source_paths: list[Path], output_path: Path) -> None:
    if len(source_paths) < 2:
        raise ReportExportError("At least two DOCX files are required for Word merge automation.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="attackcastle_word_merge_") as temp_dir:
        script_path = Path(temp_dir) / "merge-docx.ps1"
        source_json = json.dumps([str(path) for path in source_paths])
        output_json = json.dumps(str(output_path))
        script_path.write_text(
            f"""
$ErrorActionPreference = 'Stop'
$sourcePaths = @'
{source_json}
'@ | ConvertFrom-Json
$outputPath = @'
{output_json}
'@ | ConvertFrom-Json
$word = $null
$doc = $null
$shouldQuitWord = $true
$attackCastleWindowViews = @()
{_WORD_VIEW_RESTORE_PS}
function Insert-RenderedDocument {{
    param(
        [object]$TargetDocument,
        [string]$SourcePath
    )
    $range = $TargetDocument.Range()
    $range.Collapse(0)
    $range.InsertBreak(7)
    $range.Collapse(0)
    $openedSource = $null
    try {{
        $openedSource = $script:word.Documents.Open($SourcePath, $false, $true, $false)
        $content = $openedSource.Content
        if ($content.End -gt $content.Start) {{
            $content.End = $content.End - 1
        }}
        $range.FormattedText = $content.FormattedText
    }}
    catch {{
        $formattedTextError = $_.Exception.Message
        try {{
            $range.InsertFile($SourcePath)
        }}
        catch {{
            throw "Could not insert '$SourcePath'. FormattedText error: $formattedTextError. InsertFile fallback error: $($_.Exception.Message)"
        }}
    }}
    finally {{
        if ($openedSource -ne $null) {{
            $openedSource.Close($false)
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($openedSource) | Out-Null
        }}
    }}
}}
try {{
    if (Test-Path -LiteralPath $outputPath) {{
        Remove-Item -LiteralPath $outputPath -Force
    }}
    $word = New-Object -ComObject Word.Application
    $shouldQuitWord = ($word.Documents.Count -eq 0)
    $attackCastleWindowViews = Save-AttackCastleWordWindowViews $word
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $doc = $word.Documents.Open([string]$sourcePaths[0], $false, $false, $false)
    for ($index = 1; $index -lt $sourcePaths.Count; $index++) {{
        Insert-RenderedDocument $doc ([string]$sourcePaths[$index])
    }}
    try {{
        $doc.Fields.Update() | Out-Null
    }}
    catch {{
        # Field updates are best-effort; they should not block a report export.
    }}
    $doc.SaveAs2([string]$outputPath, 16)
}}
finally {{
    if ($doc -ne $null) {{
        $doc.Close($false)
    }}
    if ($word -ne $null) {{
        Restore-AttackCastleWordWindowViews $word $attackCastleWindowViews
        if ($shouldQuitWord) {{
            $word.Quit()
        }}
    }}
    if ($doc -ne $null) {{
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($doc) | Out-Null
    }}
    if ($word -ne $null) {{
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
    }}
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}}
""",
            encoding="utf-8",
        )
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script_path),
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReportExportError(f"Microsoft Word merge automation could not run: {exc}") from exc
    if result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        if details:
            raise ReportExportError(f"Microsoft Word failed to merge report templates: {details}")
        raise ReportExportError("Microsoft Word failed to merge report templates.")
    if not output_path.exists():
        raise ReportExportError("Microsoft Word did not create the merged report output.")


def _find_libreoffice_binary(explicit_path: str = "") -> str:
    candidates: list[str] = []
    if explicit_path:
        candidates.append(explicit_path)
    for env_var in _LIBREOFFICE_ENV_VARS:
        value = os.environ.get(env_var, "")
        if value:
            candidates.append(value)
    for command in _LIBREOFFICE_COMMANDS:
        resolved = shutil.which(command)
        if resolved:
            candidates.append(resolved)
    if os.name == "nt":
        candidates.extend(
            [
                r"C:\Program Files\LibreOffice\program\soffice.exe",
                r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
            ]
        )
    else:
        candidates.extend(
            [
                "/usr/bin/soffice",
                "/usr/local/bin/soffice",
                "/snap/bin/libreoffice",
                "/Applications/LibreOffice.app/Contents/MacOS/soffice",
            ]
        )
    seen: set[str] = set()
    for candidate in candidates:
        candidate = str(candidate or "").strip().strip('"')
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        path = Path(candidate).expanduser()
        if path.exists() and path.is_file():
            return str(path)
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return ""


def _merge_docx_files_with_libreoffice(source_paths: list[Path], output_path: Path, binary_path: str = "") -> None:
    if len(source_paths) < 2:
        raise ReportExportError("At least two DOCX files are required for LibreOffice merge.")
    soffice = _find_libreoffice_binary(binary_path)
    if not soffice:
        raise ReportMergeToolUnavailableError(
            "Microsoft Word or LibreOffice is required to merge multiple report templates. "
            "Install LibreOffice, then browse to the LibreOffice soffice binary when prompted."
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    python_binary = _find_libreoffice_python_binary(soffice)
    port = _free_local_port()
    script = f"""
import json
import sys
import time

import uno
from com.sun.star.beans import PropertyValue
from com.sun.star.connection import NoConnectException
from com.sun.star.text.ControlCharacter import PARAGRAPH_BREAK
from com.sun.star.style.BreakType import PAGE_BEFORE


def prop(name, value):
    item = PropertyValue()
    item.Name = name
    item.Value = value
    return item


source_paths = {json.dumps([path.resolve().as_uri() for path in source_paths])}
output_url = {json.dumps(output_path.resolve().as_uri())}
local_context = uno.getComponentContext()
resolver = local_context.ServiceManager.createInstanceWithContext(
    "com.sun.star.bridge.UnoUrlResolver",
    local_context,
)
context = None
last_error = None
for _attempt in range(60):
    try:
        context = resolver.resolve("uno:socket,host=127.0.0.1,port={port};urp;StarOffice.ComponentContext")
        break
    except NoConnectException as exc:
        last_error = exc
        time.sleep(0.5)
if context is None:
    raise RuntimeError(f"Could not connect to LibreOffice UNO listener: {{last_error}}")
desktop = context.ServiceManager.createInstanceWithContext("com.sun.star.frame.Desktop", context)
doc = desktop.loadComponentFromURL(source_paths[0], "_blank", 0, (prop("Hidden", True),))
if doc is None:
    raise RuntimeError("LibreOffice could not open the base report template.")
try:
    cursor = doc.Text.createTextCursor()
    cursor.gotoEnd(False)
    for path in source_paths[1:]:
        cursor.BreakType = PAGE_BEFORE
        doc.Text.insertControlCharacter(cursor, PARAGRAPH_BREAK, False)
        cursor.gotoEnd(False)
        cursor.insertDocumentFromURL(path, ())
        cursor.gotoEnd(False)
    doc.storeAsURL(output_url, (prop("FilterName", "Office Open XML Text"), prop("Overwrite", True)))
finally:
    doc.close(True)
"""
    with tempfile.TemporaryDirectory(prefix="attackcastle_libreoffice_merge_") as temp_dir:
        script_path = Path(temp_dir) / "merge_docx.py"
        script_path.write_text(script, encoding="utf-8")
        listener = subprocess.Popen(
            [
                soffice,
                "--headless",
                "--invisible",
                "--nologo",
                "--nodefault",
                "--nofirststartwizard",
                "--norestore",
                f"--accept=socket,host=127.0.0.1,port={port};urp;StarOffice.ComponentContext",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            result = subprocess.run(
                [python_binary, str(script_path)],
                capture_output=True,
                text=True,
                timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReportExportError(f"LibreOffice merge automation could not run: {exc}") from exc
        finally:
            listener.terminate()
            try:
                listener.wait(timeout=10)
            except subprocess.TimeoutExpired:
                listener.kill()
                listener.wait(timeout=10)
    if result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        if details:
            raise ReportExportError(f"LibreOffice failed to merge report templates: {details}")
        raise ReportExportError("LibreOffice failed to merge report templates.")
    if not output_path.exists():
        raise ReportExportError("LibreOffice did not create the merged report output.")


def _find_libreoffice_python_binary(soffice: str) -> str:
    env_value = os.environ.get("ATTACKCASTLE_LIBREOFFICE_PYTHON") or os.environ.get("LIBREOFFICE_PYTHON")
    candidates: list[str] = []
    if env_value:
        candidates.append(env_value)
    soffice_path = Path(soffice)
    if os.name == "nt":
        candidates.append(str(soffice_path.with_name("python.exe")))
    candidates.append(sys.executable)
    for candidate in candidates:
        candidate = str(candidate or "").strip().strip('"')
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if path.exists() and path.is_file():
            return str(path)
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return sys.executable


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _merge_docx_files_with_available_backend(source_paths: list[Path], output_path: Path, merge_tool_path: str = "") -> None:
    errors: list[str] = []
    if os.name == "nt" and not os.environ.get("ATTACKCASTLE_REPORTS_DISABLE_WORD_AUTOMATION") and not merge_tool_path:
        try:
            _merge_docx_files_with_word(source_paths, output_path)
            return
        except ReportExportError as exc:
            errors.append(str(exc))
    try:
        _merge_docx_files_with_libreoffice(source_paths, output_path, merge_tool_path)
        return
    except ReportMergeToolUnavailableError:
        pass
    except ReportExportError as exc:
        errors.append(str(exc))
    detail = " ".join(error for error in errors if error).strip()
    suffix = f" Last error: {detail}" if detail else ""
    raise ReportMergeToolUnavailableError(
        "Microsoft Word or LibreOffice is required to merge multiple report templates. "
        "Install LibreOffice, or provide the path to the LibreOffice soffice binary."
        + suffix
    )


def _convert_docx_to_pdf_with_word(source_path: Path, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="attackcastle_word_pdf_") as temp_dir:
        script_path = Path(temp_dir) / "convert-docx-pdf.ps1"
        source_json = json.dumps(str(source_path))
        output_json = json.dumps(str(output_path))
        script_path.write_text(
            f"""
$ErrorActionPreference = 'Stop'
$sourcePath = @'
{source_json}
'@ | ConvertFrom-Json
$outputPath = @'
{output_json}
'@ | ConvertFrom-Json
$word = $null
$doc = $null
$shouldQuitWord = $true
$attackCastleWindowViews = @()
{_WORD_VIEW_RESTORE_PS}
try {{
    if (Test-Path -LiteralPath $outputPath) {{
        Remove-Item -LiteralPath $outputPath -Force
    }}
    $word = New-Object -ComObject Word.Application
    $shouldQuitWord = ($word.Documents.Count -eq 0)
    $attackCastleWindowViews = Save-AttackCastleWordWindowViews $word
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $doc = $word.Documents.Open([string]$sourcePath, $false, $true, $false)
    $doc.SaveAs2([string]$outputPath, 17)
}}
finally {{
    if ($doc -ne $null) {{
        $doc.Close($false)
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($doc) | Out-Null
    }}
    if ($word -ne $null) {{
        Restore-AttackCastleWordWindowViews $word $attackCastleWindowViews
        if ($shouldQuitWord) {{
            $word.Quit()
        }}
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
    }}
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}}
""",
            encoding="utf-8",
        )
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script_path),
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReportConversionUnavailableError(f"Microsoft Word PDF conversion could not run: {exc}") from exc
    if result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        raise ReportConversionUnavailableError(f"Microsoft Word failed to convert the report to PDF: {details}" if details else "Microsoft Word failed to convert the report to PDF.")
    if not output_path.exists():
        raise ReportConversionUnavailableError("Microsoft Word did not create the PDF output.")


def _convert_docx_to_pdf_with_libreoffice(source_path: Path, output_path: Path, binary_path: str = "") -> None:
    soffice = _find_libreoffice_binary(binary_path)
    if not soffice:
        raise ReportConversionUnavailableError("LibreOffice is required to export PDF when Microsoft Word is unavailable.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="attackcastle_libreoffice_pdf_") as temp_dir:
        temp_output_dir = Path(temp_dir)
        try:
            result = subprocess.run(
                [
                    soffice,
                    "--headless",
                    "--convert-to",
                    "pdf",
                    "--outdir",
                    str(temp_output_dir),
                    str(source_path),
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReportConversionUnavailableError(f"LibreOffice PDF conversion could not run: {exc}") from exc
        if result.returncode != 0:
            details = (result.stderr or result.stdout or "").strip()
            raise ReportConversionUnavailableError(f"LibreOffice failed to convert the report to PDF: {details}" if details else "LibreOffice failed to convert the report to PDF.")
        converted = temp_output_dir / f"{source_path.stem}.pdf"
        if not converted.exists():
            raise ReportConversionUnavailableError("LibreOffice did not create the PDF output.")
        shutil.move(str(converted), str(output_path))


def convert_docx_to_pdf(source_path: Path, output_path: Path | None = None, *, merge_tool_path: str = "") -> Path:
    source_path = Path(source_path).expanduser().resolve()
    if not source_path.exists():
        raise ReportConversionUnavailableError(f"DOCX source not found: {source_path}")
    target = (output_path or source_path.with_suffix(".pdf")).expanduser().resolve()
    errors: list[str] = []
    if os.name == "nt" and not os.environ.get("ATTACKCASTLE_REPORTS_DISABLE_WORD_AUTOMATION") and not merge_tool_path:
        try:
            _convert_docx_to_pdf_with_word(source_path, target)
            return target
        except ReportConversionUnavailableError as exc:
            errors.append(str(exc))
    try:
        _convert_docx_to_pdf_with_libreoffice(source_path, target, merge_tool_path)
        return target
    except ReportConversionUnavailableError as exc:
        errors.append(str(exc))
    detail = " ".join(error for error in errors if error).strip()
    suffix = f" Last error: {detail}" if detail else ""
    raise ReportConversionUnavailableError(
        "Microsoft Word or LibreOffice is required to export PDF."
        + suffix
    )


def _merge_backend_enabled(explicit: bool | None) -> bool:
    return explicit is not False


def export_report(
    *,
    export_path: str,
    report_title: str,
    report_type: str,
    client_name: str,
    report_date: str,
    workspace_home: str = "",
    sections: list[ReportTemplateSection] | None = None,
    included_findings: list[dict[str, Any]] | None = None,
    use_word_automation: bool | None = None,
    merge_tool_path: str = "",
) -> ReportExportResult:
    selected_findings = list(included_findings or [])
    replacements = build_shortcode_values(
        report_title=report_title,
        report_type=report_type,
        client_name=client_name,
        report_date=report_date,
        included_findings=selected_findings,
    )
    counts = _severity_counts(selected_findings)
    output_path = resolve_output_path(
        export_path,
        workspace_home=workspace_home,
        client_name=client_name,
        report_title=report_title,
        report_date=report_date,
    )
    enabled_sections = [section for section in (sections or DEFAULT_SECTIONS) if section.enabled]
    if not enabled_sections:
        raise ReportExportError("No report template sections are enabled.")
    template_paths = [_template_path_for_section(section) for section in enabled_sections]
    missing = [path for path in template_paths if not path.exists()]
    if missing:
        raise ReportExportError(f"Template not found: {missing[0]}")
    if len(enabled_sections) == 1:
        _write_docx(_render_docx_template_bytes(template_paths[0], replacements, counts), output_path)
    elif _merge_backend_enabled(use_word_automation) or merge_tool_path:
        with tempfile.TemporaryDirectory(prefix="attackcastle_reports_rendered_") as temp_dir:
            rendered_paths: list[Path] = []
            for index, template_path in enumerate(template_paths):
                rendered_path = Path(temp_dir) / f"{index:02d}_{template_path.name}"
                _render_docx_template_file(template_path, rendered_path, replacements, counts)
                rendered_paths.append(rendered_path)
            _merge_docx_files_with_available_backend(rendered_paths, output_path, merge_tool_path)
    else:
        rendered_sections = [
            (section.section_id, _render_docx_template_bytes(template_path, replacements, counts))
            for section, template_path in zip(enabled_sections, template_paths)
        ]
        base_parts = _append_docx_sections_as_alt_chunks(rendered_sections[0][1], rendered_sections[1:])
        _write_docx(base_parts, output_path)
    return ReportExportResult(
        output_path=output_path,
        template_paths=template_paths,
        shortcode_values=replacements,
        included_findings=selected_findings,
    )
