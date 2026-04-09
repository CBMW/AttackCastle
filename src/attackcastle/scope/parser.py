from __future__ import annotations

import re
from dataclasses import dataclass

from attackcastle.core.models import ScanTarget
from attackcastle.scope.classifier import classify_target


@dataclass
class ScopeValidationSummary:
    total_entries: int
    valid_entries: int
    invalid_entries: int
    duplicates_removed: int
    by_type: dict[str, int]
    invalid_values: list[str]
    deduped_targets: list[ScanTarget]


def split_target_input(raw_input: str) -> list[str]:
    return [part.strip() for part in re.split(r"[\n,]+", raw_input) if part.strip()]


def parse_target_input(raw_input: str, forced_type: str | None = None) -> list[ScanTarget]:
    parts = split_target_input(raw_input)
    if not parts:
        return []
    return [classify_target(part, forced_type=forced_type) for part in parts]


def summarize_target_input(raw_input: str, forced_type: str | None = None) -> ScopeValidationSummary:
    parts = split_target_input(raw_input)
    by_type: dict[str, int] = {}
    invalid_values: list[str] = []
    deduped_targets: list[ScanTarget] = []
    seen: set[tuple[str, str, str | None, int | None, str | None]] = set()

    for part in parts:
        try:
            target = classify_target(part, forced_type=forced_type)
        except ValueError:
            invalid_values.append(part)
            continue
        if target.target_type.value == "unknown":
            invalid_values.append(part)
            continue
        by_type[target.target_type.value] = by_type.get(target.target_type.value, 0) + 1
        key = (
            target.target_type.value,
            target.value,
            target.host,
            target.port,
            target.scheme,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped_targets.append(target)

    valid_entries = sum(by_type.values())
    duplicates_removed = max(valid_entries - len(deduped_targets), 0)
    return ScopeValidationSummary(
        total_entries=len(parts),
        valid_entries=len(deduped_targets),
        invalid_entries=len(invalid_values),
        duplicates_removed=duplicates_removed,
        by_type=by_type,
        invalid_values=invalid_values,
        deduped_targets=deduped_targets,
    )
