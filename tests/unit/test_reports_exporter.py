from __future__ import annotations

import io
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from attackcastle.extensions.reports.exporter import (
    ReportExportError,
    ReportMergeToolUnavailableError,
    _find_libreoffice_binary,
    _replace_shortcodes_in_xml,
    export_report,
    resolve_output_path,
)
from attackcastle.extensions.reports.models import ReportTemplateSection


def _document_xml(path: Path) -> str:
    with zipfile.ZipFile(path, "r") as archive:
        return archive.read("word/document.xml").decode("utf-8")


def _xml_parts(path: Path, prefix: str) -> list[str]:
    with zipfile.ZipFile(path, "r") as archive:
        return [
            archive.read(name).decode("utf-8")
            for name in archive.namelist()
            if name.startswith(prefix) and name.endswith(".xml")
        ]


def _embedded_docx_xml_parts(path: Path) -> list[str]:
    xml_parts: list[str] = []
    with zipfile.ZipFile(path, "r") as archive:
        chunk_names = [
            name
            for name in archive.namelist()
            if name.startswith("word/attackcastle_") and name.endswith(".docx")
        ]
        for chunk_name in chunk_names:
            with zipfile.ZipFile(archive.open(chunk_name), "r") as embedded:
                xml_parts.extend(
                    embedded.read(name).decode("utf-8")
                    for name in embedded.namelist()
                    if name.startswith("word/") and name.endswith(".xml")
                )
    return xml_parts


def test_reports_exporter_replaces_cover_page_shortcodes(tmp_path: Path) -> None:
    output_path = tmp_path / "alpha-report.docx"

    result = export_report(
        export_path=str(output_path),
        report_title="Alpha Web Assessment",
        report_type="Web Application, External",
        client_name="Alpha Pty Ltd",
        report_date="21/04/2026",
        included_findings=[{"finding_id": "f-1"}],
        use_word_automation=False,
    )

    xml = _document_xml(output_path)
    assert result.output_path == output_path.resolve()
    assert "Alpha Web Assessment" in xml
    assert "Web Application, External" in xml
    assert "Alpha Pty Ltd" in xml
    assert "21/04/2026" in xml
    assert "%%report_title%%" not in xml
    assert "Table of Contents" in "\n".join(_embedded_docx_xml_parts(output_path))
    assert len(result.template_paths) == 3
    assert result.included_findings == [{"finding_id": "f-1"}]


def test_reports_exporter_preserves_template_breaks_and_run_formatting(tmp_path: Path) -> None:
    output_path = tmp_path / "formatted-cover.docx"
    template_path = Path("src/attackcastle/extensions/reports/templates/cover_page.docx")
    before = _document_xml(template_path)

    export_report(
        export_path=str(output_path),
        report_title="Miyagi AI",
        report_type="Web Application",
        client_name="testing",
        report_date="21/04/2026",
        use_word_automation=False,
    )

    after = _document_xml(output_path)
    assert after.count("<w:br") >= before.count("<w:br")
    assert after.count("<w:rPr") >= before.count("<w:rPr")
    assert "Miyagi AI" in after
    assert "Web Application" in after
    assert "testing" in after
    assert "21/04/2026" in after


def test_reports_exporter_replaces_shortcodes_inside_chapter_headers(tmp_path: Path) -> None:
    output_path = tmp_path / "with-chapter.docx"

    export_report(
        export_path=str(output_path),
        report_title="Miyagi AI",
        report_type="Web Application",
        client_name="testing",
        report_date="21/04/2026",
        use_word_automation=False,
    )

    headers = "\n".join(_embedded_docx_xml_parts(output_path))
    assert "Miyagi AI" in headers
    assert "Web Application" in headers
    assert "%%report_title%%" not in headers
    assert "%%report_type%%" not in headers


def test_reports_exporter_appends_chapter_as_valid_alt_chunk(tmp_path: Path) -> None:
    output_path = tmp_path / "valid-altchunk.docx"

    export_report(
        export_path=str(output_path),
        report_title="Miyagi AI",
        report_type="Web Application",
        client_name="testing",
        report_date="21/04/2026",
        use_word_automation=False,
    )

    with zipfile.ZipFile(output_path, "r") as archive:
        names = set(archive.namelist())
        document_xml = archive.read("word/document.xml").decode("utf-8")
        rels_xml = archive.read("word/_rels/document.xml.rels").decode("utf-8")
        content_types = archive.read("[Content_Types].xml").decode("utf-8")
        chunk_names = [name for name in names if name.startswith("word/attackcastle_") and name.endswith(".docx")]

        assert len(chunk_names) == 2
        assert "<w:altChunk" in document_xml
        assert "relationships/aFChunk" in rels_xml
        assert f'PartName="/{chunk_names[0]}"' in content_types
        assert "application/vnd.openxmlformats-officedocument.wordprocessingml.document" in content_types
        assert "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml" not in content_types.split(f'PartName="/{chunk_names[0]}"', 1)[1].split("/>", 1)[0]
        with zipfile.ZipFile(archive.open(chunk_names[0]), "r") as embedded:
            assert "word/document.xml" in embedded.namelist()


def test_reports_exporter_updates_management_summary_chart_counts(tmp_path: Path) -> None:
    output_path = tmp_path / "chapter-chart.docx"

    result = export_report(
        export_path=str(output_path),
        report_title="Alpha",
        report_type="External",
        client_name="Alpha",
        report_date="21/04/2026",
        sections=[ReportTemplateSection(section_id="chapter1_1", template_filename="chapter1-1.docx")],
        included_findings=[
            {"finding_id": "c", "severity": "critical"},
            {"finding_id": "h1", "severity": "high"},
            {"finding_id": "h2", "effective_severity": "high"},
            {"finding_id": "m", "severity": "medium"},
            {"finding_id": "i", "severity": "info"},
        ],
        use_word_automation=False,
    )

    xml = _document_xml(output_path)
    assert result.shortcode_values["%%vulnerability_counts1%%"] == "5"
    assert result.shortcode_values["%%overall_exposure%%"] == "Critical"
    assert "%%vulnerability_counts1%%" not in xml
    with zipfile.ZipFile(output_path, "r") as archive:
        chart_xml = archive.read("word/charts/chart1.xml").decode("utf-8")
        embedded = archive.read("word/embeddings/Microsoft_Excel_Worksheet.xlsx")
    numeric_cache = chart_xml.split("<c:numCache>", 1)[1].split("</c:numCache>", 1)[0]
    assert "<c:pt idx=\"0\"><c:v>1</c:v></c:pt>" in numeric_cache
    assert "<c:pt idx=\"1\"><c:v>2</c:v></c:pt>" in numeric_cache
    assert "<c:pt idx=\"2\"><c:v>1</c:v></c:pt>" in numeric_cache
    assert "<c:pt idx=\"3\">" not in numeric_cache
    assert "<c:pt idx=\"4\"><c:v>1</c:v></c:pt>" in numeric_cache
    with zipfile.ZipFile(io.BytesIO(embedded), "r") as workbook:
        sheet_xml = workbook.read("xl/worksheets/sheet1.xml").decode("utf-8")
    sheet_root = ET.fromstring(sheet_xml)
    ns = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    assert [sheet_root.find(f".//x:c[@r='B{row}']/x:v", ns).text for row in (2, 3, 4, 6)] == ["1", "2", "1", "1"]
    assert sheet_root.find(".//x:c[@r='B5']/x:v", ns) is None


def test_shortcode_replacement_preserves_split_runs_and_line_breaks() -> None:
    xml = (
        '<w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%%</w:t></w:r>'
        '<w:r><w:rPr><w:b/></w:rPr><w:t>report_title</w:t></w:r>'
        '<w:r><w:rPr><w:b/></w:rPr><w:t>%%</w:t></w:r>'
        '<w:r><w:t> - </w:t></w:r><w:r><w:br/></w:r>'
        '<w:r><w:rPr><w:i/></w:rPr><w:t>%%client_name%%</w:t></w:r></w:p>'
    )

    replaced = _replace_shortcodes_in_xml(
        xml,
        {
            "%%report_title%%": "Alpha",
            "%%client_name%%": "Client & Co",
        },
    )

    assert "<w:br/>" in replaced
    assert replaced.count("<w:rPr") == xml.count("<w:rPr")
    assert "<w:t>Alpha</w:t>" in replaced
    assert "<w:t>Client &amp; Co</w:t>" in replaced
    assert "%%report_title%%" not in replaced
    assert "%%client_name%%" not in replaced


def test_reports_exporter_resolves_directory_export_path(tmp_path: Path) -> None:
    output_path = resolve_output_path(
        str(tmp_path),
        client_name="Alpha Pty Ltd",
        report_title="External / Internal",
        report_date="21/04/2026",
    )

    assert output_path.parent == tmp_path.resolve()
    assert output_path.name == "Alpha_Pty_Ltd_External_Internal_21042026.docx"


def test_reports_exporter_requires_export_path() -> None:
    with pytest.raises(ReportExportError, match="Export path"):
        export_report(
            export_path="",
            report_title="Alpha",
            report_type="External",
            client_name="Alpha",
            report_date="21/04/2026",
            use_word_automation=False,
        )


def test_reports_exporter_resolves_explicit_libreoffice_binary(tmp_path: Path) -> None:
    binary = tmp_path / ("soffice.exe" if "\\" in str(tmp_path) else "soffice")
    binary.write_text("", encoding="utf-8")

    assert _find_libreoffice_binary(str(binary)) == str(binary)


def test_reports_exporter_reports_missing_merge_backend(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ATTACKCASTLE_REPORTS_DISABLE_WORD_AUTOMATION", "1")
    monkeypatch.setattr("attackcastle.extensions.reports.exporter._find_libreoffice_binary", lambda _path="": "")
    output_path = tmp_path / "missing-backend.docx"

    with pytest.raises(ReportMergeToolUnavailableError, match="LibreOffice"):
        export_report(
            export_path=str(output_path),
            report_title="Alpha",
            report_type="External",
            client_name="Alpha",
            report_date="21/04/2026",
        )
