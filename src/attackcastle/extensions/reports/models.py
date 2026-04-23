from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ReportTemplateSection:
    section_id: str
    template_filename: str
    enabled: bool = True
    shortcodes: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ReportExportResult:
    output_path: Path
    template_paths: list[Path]
    shortcode_values: dict[str, str]
    included_findings: list[dict[str, Any]] = field(default_factory=list)
