from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from attackcastle.core.models import to_serializable


class FileCache:
    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _path_for_key(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def get(self, key: str) -> Any | None:
        path = self._path_for_key(key)
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def set(self, key: str, value: Any) -> Path:
        path = self._path_for_key(key)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(to_serializable(value), handle, indent=2)
        return path

