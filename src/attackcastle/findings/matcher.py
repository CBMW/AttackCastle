from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from attackcastle.core.models import Observation, RunData


def build_observation_index(run_data: RunData) -> dict[tuple[str, str], dict[str, list[Any]]]:
    index: dict[tuple[str, str], dict[str, list[Any]]] = defaultdict(lambda: defaultdict(list))
    for observation in run_data.observations:
        key = (observation.entity_type, observation.entity_id)
        index[key][observation.key].append(observation.value)
    return index


def _match_value(op: str, observed_values: list[Any], condition_value: Any | None) -> bool:
    if op == "exists":
        return len(observed_values) > 0
    if not observed_values:
        return False

    if op == "eq":
        return any(value == condition_value for value in observed_values)
    if op == "neq":
        return any(value != condition_value for value in observed_values)
    if op == "in":
        if not isinstance(condition_value, list):
            return False
        return any(value in condition_value for value in observed_values)
    if op == "contains":
        return any(str(condition_value).lower() in str(value).lower() for value in observed_values)
    if op == "contains_any":
        if not isinstance(condition_value, list):
            return False
        for value in observed_values:
            if isinstance(value, list):
                lowered = [str(item).lower() for item in value]
                if any(str(candidate).lower() in lowered for candidate in condition_value):
                    return True
            if any(str(candidate).lower() in str(value).lower() for candidate in condition_value):
                return True
        return False
    if op == "regex":
        pattern = re.compile(str(condition_value), re.IGNORECASE)
        return any(pattern.search(str(value)) for value in observed_values)
    if op == "gt":
        return any(float(value) > float(condition_value) for value in observed_values)
    if op == "gte":
        return any(float(value) >= float(condition_value) for value in observed_values)
    if op == "lt":
        return any(float(value) < float(condition_value) for value in observed_values)
    if op == "lte":
        return any(float(value) <= float(condition_value) for value in observed_values)
    if op == "length_gte":
        return any(isinstance(value, list) and len(value) >= int(condition_value) for value in observed_values)
    return False


def match_entities_for_template(
    template: dict[str, Any],
    index: dict[tuple[str, str], dict[str, list[Any]]],
) -> list[str]:
    trigger = template["trigger"]
    entity_type = trigger["entity_type"]
    logic = trigger.get("logic", "all")
    conditions = trigger.get("conditions", [])

    matched_entity_ids: list[str] = []
    for (candidate_type, entity_id), values_by_key in index.items():
        if candidate_type != entity_type:
            continue
        checks: list[bool] = []
        for condition in conditions:
            key = condition["key"]
            op = condition["op"]
            expected_value = condition.get("value")
            observed_values = values_by_key.get(key, [])
            checks.append(_match_value(op, observed_values, expected_value))
        if not checks:
            continue
        if logic == "all" and all(checks):
            matched_entity_ids.append(entity_id)
        elif logic == "any" and any(checks):
            matched_entity_ids.append(entity_id)
    return matched_entity_ids


def select_observations_for_entity(
    run_data: RunData,
    entity_type: str,
    entity_id: str,
    keys: list[str],
) -> list[Observation]:
    selected: list[Observation] = []
    key_set = set(keys)
    for observation in run_data.observations:
        if observation.entity_type != entity_type or observation.entity_id != entity_id:
            continue
        if not key_set or observation.key in key_set:
            selected.append(observation)
    return selected

