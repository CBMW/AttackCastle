from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import QObject, Signal, Slot


class AssetGraphBridge(QObject):
    nodeSelected = Signal(dict)
    graphReady = Signal()

    @Slot(str)
    def onNodeSelected(self, payload: str) -> None:  # noqa: N802
        try:
            parsed = json.loads(payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed = {}
        if isinstance(parsed, dict):
            self.nodeSelected.emit(parsed)

    @Slot()
    def onGraphReady(self) -> None:  # noqa: N802
        self.graphReady.emit()

    @staticmethod
    def to_json(payload: dict[str, Any]) -> str:
        return json.dumps(payload, sort_keys=True)
