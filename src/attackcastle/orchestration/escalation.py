from __future__ import annotations

from typing import Any

from attackcastle.core.models import RunData


def _detected_technologies(run_data: RunData) -> set[str]:
    detected = {str(tech.name).strip().lower() for tech in run_data.technologies if tech.name}
    for observation in run_data.observations:
        if not observation.key.startswith("tech.") or not observation.key.endswith(".detected"):
            continue
        if observation.value is not True:
            continue
        middle = observation.key[len("tech.") : -len(".detected")]
        normalized = middle.replace("_", " ").replace("-", " ").strip().lower()
        if normalized:
            detected.add(normalized)
    return detected


def task_allowed_by_matrix(task_key: str, run_data: RunData, config: dict[str, Any]) -> tuple[bool, str]:
    escalation = config.get("escalation", {})
    if not isinstance(escalation, dict):
        return True, "escalation_matrix_disabled"
    matrix = escalation.get("matrix", {})
    if not isinstance(matrix, dict) or not matrix:
        return True, "escalation_matrix_empty"

    task_to_triggers: dict[str, set[str]] = {}
    for tech_name, entry in matrix.items():
        tasks: list[str] = []
        if isinstance(entry, dict):
            task_values = entry.get("tasks", [])
            if isinstance(task_values, list):
                tasks = [str(item) for item in task_values]
        elif isinstance(entry, list):
            tasks = [str(item) for item in entry]
        for task in tasks:
            task_to_triggers.setdefault(task, set()).add(str(tech_name).lower())

    if task_key not in task_to_triggers:
        return True, "task_not_controlled_by_matrix"

    detected = _detected_technologies(run_data)
    required_tokens = task_to_triggers[task_key]
    matched_tokens = {
        token
        for token in required_tokens
        if token in detected or any(token in detected_item for detected_item in detected)
    }
    if matched_tokens:
        return True, f"matrix_trigger_matched:{','.join(sorted(matched_tokens))}"
    return False, f"waiting_for_matrix_trigger:{','.join(sorted(required_tokens))}"

