from __future__ import annotations

from pathlib import Path

from attackcastle.storage.run_store import RunStore


class ArtifactManager:
    def __init__(self, run_store: RunStore) -> None:
        self.run_store = run_store

    def write_tool_text(self, tool_name: str, file_name: str, content: str) -> Path:
        path = self.run_store.artifact_path(tool_name, file_name)
        path.write_text(content, encoding="utf-8")
        return path

    def write_tool_bytes(self, tool_name: str, file_name: str, content: bytes) -> Path:
        path = self.run_store.artifact_path(tool_name, file_name)
        path.write_bytes(content)
        return path

