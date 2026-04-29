from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attackcastle.findings.rule_schema import normalize_definition, validate_detection
from attackcastle.findings.schema import load_templates_from_dirs, validate_template


def builtin_findings_template_dir() -> Path:
    return Path(__file__).resolve().parent / "templates"


def default_user_findings_template_dir() -> Path:
    return Path.home() / ".attackcastle" / "findings" / "templates"


def definition_filename(definition_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(definition_id or "").strip())
    cleaned = cleaned.strip("._-") or "finding"
    return f"{cleaned}.json"


@dataclass(slots=True)
class FindingLibraryResult:
    definitions: list[dict[str, Any]]
    warnings: list[str] = field(default_factory=list)


class FindingLibraryStore:
    def __init__(
        self,
        *,
        builtin_dir: Path | None = None,
        user_dir: Path | None = None,
    ) -> None:
        self.builtin_dir = builtin_dir or builtin_findings_template_dir()
        self.user_dir = user_dir or default_user_findings_template_dir()

    def load_definitions(self) -> FindingLibraryResult:
        warnings: list[str] = []
        warnings.extend(self._file_warnings(self.builtin_dir))
        warnings.extend(self._file_warnings(self.user_dir))
        definitions: list[dict[str, Any]] = []
        try:
            definitions = load_templates_from_dirs([self.builtin_dir, self.user_dir])
        except Exception as exc:  # noqa: BLE001
            warnings.append(str(exc))
            try:
                definitions = load_templates_from_dirs([self.builtin_dir])
            except Exception as fallback_exc:  # noqa: BLE001
                warnings.append(str(fallback_exc))
                definitions = []

        normalized: list[dict[str, Any]] = []
        for definition in definitions:
            definition_id = str(definition.get("id") or "<unknown>")
            try:
                validate_template(definition)
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"{definition_id}: {exc}")
                continue
            detection_issues = validate_detection(definition)
            if detection_issues:
                warnings.extend(f"{definition_id}: {issue}" for issue in detection_issues)
                continue
            normalized.append(normalize_definition(definition))
        return FindingLibraryResult(definitions=normalized, warnings=warnings)

    def _file_warnings(self, directory: Path) -> list[str]:
        if not directory.exists():
            return []
        warnings: list[str] = []
        for path in sorted(directory.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"{path.name}: invalid JSON: {exc}")
                continue
            if not isinstance(payload, dict):
                warnings.append(f"{path.name}: definition must be a JSON object")
            elif not str(payload.get("id") or "").strip():
                warnings.append(f"{path.name}: missing finding id")
        return warnings

    def user_definition_path(self, definition_id: str) -> Path:
        return self.user_dir / definition_filename(definition_id)

    def save_definition(self, definition: dict[str, Any]) -> Path:
        normalized = normalize_definition(definition)
        definition_id = str(normalized.get("id") or "").strip()
        if not definition_id:
            raise ValueError("Finding id is required")
        validate_template(normalized)
        issues = validate_detection(normalized)
        if issues:
            raise ValueError("; ".join(issues))
        self.user_dir.mkdir(parents=True, exist_ok=True)
        path = self.user_definition_path(definition_id)
        path.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def delete_definition(self, definition_id: str) -> bool:
        path = self.user_definition_path(definition_id)
        if not path.exists():
            return False
        path.unlink()
        return True

    def is_user_definition(self, definition_id: str) -> bool:
        return self.user_definition_path(definition_id).exists()
