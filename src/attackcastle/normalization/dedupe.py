from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any


def make_key(*parts: Any) -> str:
    normalized: list[Any] = []
    for part in parts:
        if isinstance(part, (dict, list)):
            normalized.append(json.dumps(part, sort_keys=True, default=str))
        else:
            normalized.append(part)
    return "|".join("" if value is None else str(value) for value in normalized)


def dataclass_key(obj: Any, fields: list[str]) -> str:
    data = asdict(obj)
    return make_key(*(data.get(field) for field in fields))

