from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attackcastle.gui.models import AuditEntry, EntityNote, FindingState, MigrationState, RunRegistryEntry, Workspace, now_iso

WORKSPACE_STORE_VERSION = 4
LEGACY_WORKSPACE_STORE_VERSION = 2
NO_WORKSPACE_SCOPE_ID = "__no_workspace__"


def default_workspace_store_path() -> Path:
    return Path.home() / ".attackcastle" / "gui_workspace.json"


def default_workspace_home(workspace_id: str) -> str:
    return str((Path.home() / ".attackcastle" / "workspaces" / workspace_id).resolve())


def ad_hoc_output_home() -> str:
    return str((Path.home() / ".attackcastle" / "ad_hoc").resolve())


def resolve_workspace_scope(workspace_id: str | None) -> str:
    return str(workspace_id or "").strip() or NO_WORKSPACE_SCOPE_ID


def _is_synthetic_default_workspace(workspace: Workspace) -> bool:
    return workspace.workspace_id == "ws_default" and workspace.name == "Default Workspace"


def _workspace_has_meaningful_data(workspace: Workspace, payload: dict[str, Any]) -> bool:
    if any(
        (
            workspace.client_name.strip(),
            workspace.scope_summary.strip(),
            workspace.last_opened_at.strip(),
        )
    ):
        return True
    for section_name in ("run_registry", "finding_states", "entity_notes", "audit"):
        section = payload.get(section_name, {})
        if isinstance(section, dict) and section.get(workspace.workspace_id):
            return True
    return False


def _prune_synthetic_default_workspaces(workspaces: list[Workspace], payload: dict[str, Any]) -> list[Workspace]:
    if len(workspaces) != 1:
        return workspaces
    workspace = workspaces[0]
    if _is_synthetic_default_workspace(workspace) and not _workspace_has_meaningful_data(workspace, payload):
        return []
    return workspaces


def _default_payload() -> dict[str, Any]:
    return {
        "version": WORKSPACE_STORE_VERSION,
        "active_workspace_id": "",
        "workspaces": [],
        "run_registry": {NO_WORKSPACE_SCOPE_ID: []},
        "finding_states": {NO_WORKSPACE_SCOPE_ID: {}},
        "entity_notes": {NO_WORKSPACE_SCOPE_ID: {}},
        "audit": {NO_WORKSPACE_SCOPE_ID: []},
        "ui_layout": {},
        "migration_state": MigrationState(completed=True).to_dict(),
    }


def _uses_workspace_model(payload: dict[str, Any]) -> bool:
    version = int(payload.get("version", 1) or 1)
    return version >= LEGACY_WORKSPACE_STORE_VERSION and isinstance(payload.get("workspaces"), list)


class WorkspaceStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_workspace_store_path()

    def _read_payload(self) -> dict[str, Any]:
        if not self.path.exists():
            return _default_payload()
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return _default_payload()
        if not isinstance(loaded, dict):
            return _default_payload()
        return loaded

    def _write_payload(self, payload: dict[str, Any]) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return self.path

    def migration_required(self) -> bool:
        payload = self._read_payload()
        version = int(payload.get("version", 1) or 1)
        if version < LEGACY_WORKSPACE_STORE_VERSION:
            return True
        if not _uses_workspace_model(payload):
            return True
        if version < WORKSPACE_STORE_VERSION:
            return False
        migration_state = MigrationState.from_dict(payload.get("migration_state", {}))
        return not migration_state.completed

    def load_migration_state(self) -> MigrationState:
        payload = self._read_payload()
        return MigrationState.from_dict(payload.get("migration_state", {}))

    def save_migration_state(self, state: MigrationState) -> Path:
        payload = self._normalized_payload()
        payload["migration_state"] = state.to_dict()
        return self._write_payload(payload)

    def scope_key(self, workspace_id: str | None = None) -> str:
        return resolve_workspace_scope(workspace_id)

    def load_legacy_payload(self) -> dict[str, Any]:
        payload = self._read_payload()
        if _uses_workspace_model(payload):
            return {}
        return payload

    def _normalized_payload(self) -> dict[str, Any]:
        payload = self._read_payload()
        version = int(payload.get("version", 1) or 1)
        if version < LEGACY_WORKSPACE_STORE_VERSION or not isinstance(payload.get("workspaces"), list):
            # Return a normalized v2 shell without destroying legacy data until migration completes.
            normalized = _default_payload()
            migration_state = MigrationState(
                completed=False,
                last_detected_legacy_version=version,
            )
            normalized["migration_state"] = migration_state.to_dict()
            return normalized

        workspaces = self.load_workspaces()
        payload["version"] = WORKSPACE_STORE_VERSION
        payload["workspaces"] = [workspace.to_dict() for workspace in workspaces]
        active_workspace_id = str(payload.get("active_workspace_id") or "")
        if active_workspace_id not in {workspace.workspace_id for workspace in workspaces}:
            payload["active_workspace_id"] = ""
        payload["run_registry"] = self._normalized_run_registry(payload.get("run_registry"), workspaces)
        payload["finding_states"] = self._normalized_finding_states(payload.get("finding_states"), workspaces)
        payload["entity_notes"] = self._normalized_entity_notes(payload.get("entity_notes"), workspaces)
        payload["audit"] = self._normalized_audit(payload.get("audit"), workspaces)
        payload["ui_layout"] = self._normalized_ui_layout(payload.get("ui_layout"))
        migration_state = MigrationState.from_dict(payload.get("migration_state", {}))
        if version < WORKSPACE_STORE_VERSION:
            migration_state.completed = True
            migration_state.last_detected_legacy_version = max(migration_state.last_detected_legacy_version, version)
        payload["migration_state"] = migration_state.to_dict()
        return payload

    def _normalized_ui_layout(self, raw: Any) -> dict[str, dict[str, list[int]]]:
        if not isinstance(raw, dict):
            return {}
        result: dict[str, dict[str, list[int]]] = {}
        for layout_key, orientations in raw.items():
            if not isinstance(layout_key, str) or not isinstance(orientations, dict):
                continue
            normalized_orientations: dict[str, list[int]] = {}
            for orientation, sizes in orientations.items():
                if orientation not in {"horizontal", "vertical"} or not isinstance(sizes, list):
                    continue
                normalized_sizes: list[int] = []
                for size in sizes:
                    if not isinstance(size, (int, float)):
                        normalized_sizes = []
                        break
                    normalized_sizes.append(max(int(size), 0))
                if any(value > 0 for value in normalized_sizes):
                    normalized_orientations[orientation] = normalized_sizes
            if normalized_orientations:
                result[layout_key] = normalized_orientations
        return result

    def _normalized_run_registry(self, raw: Any, workspaces: list[Workspace]) -> dict[str, list[dict[str, Any]]]:
        valid_ids = {workspace.workspace_id for workspace in workspaces}
        result: dict[str, list[dict[str, Any]]] = {NO_WORKSPACE_SCOPE_ID: []}
        result.update({workspace.workspace_id: [] for workspace in workspaces})
        if not isinstance(raw, dict):
            return result
        for workspace_id, items in raw.items():
            if workspace_id not in valid_ids and workspace_id != NO_WORKSPACE_SCOPE_ID:
                continue
            if not isinstance(items, list):
                continue
            rows: list[dict[str, Any]] = []
            for entry in (RunRegistryEntry.from_dict(item) for item in items if isinstance(item, dict)):
                if not entry.run_id or not entry.run_dir:
                    continue
                if workspace_id == NO_WORKSPACE_SCOPE_ID:
                    entry.workspace_id = ""
                elif not entry.workspace_id:
                    entry.workspace_id = workspace_id
                rows.append(entry.to_dict())
            result[workspace_id] = rows
        return result

    def _normalized_finding_states(self, raw: Any, workspaces: list[Workspace]) -> dict[str, dict[str, dict[str, Any]]]:
        valid_ids = {workspace.workspace_id for workspace in workspaces}
        result: dict[str, dict[str, dict[str, Any]]] = {NO_WORKSPACE_SCOPE_ID: {}}
        result.update({workspace.workspace_id: {} for workspace in workspaces})
        if not isinstance(raw, dict):
            return result
        for workspace_id, items in raw.items():
            if workspace_id not in valid_ids and workspace_id != NO_WORKSPACE_SCOPE_ID:
                continue
            if not isinstance(items, dict):
                continue
            workspace_states: dict[str, dict[str, Any]] = {}
            for run_id, states in items.items():
                if not isinstance(run_id, str) or not isinstance(states, dict):
                    continue
                workspace_states[run_id] = {
                    finding_id: state.to_dict()
                    for finding_id, state in (
                        (finding_id, FindingState.from_dict(payload))
                        for finding_id, payload in states.items()
                        if isinstance(finding_id, str) and isinstance(payload, dict)
                    )
                }
            result[workspace_id] = workspace_states
        return result

    def _normalized_entity_notes(self, raw: Any, workspaces: list[Workspace]) -> dict[str, dict[str, dict[str, Any]]]:
        valid_ids = {workspace.workspace_id for workspace in workspaces}
        result: dict[str, dict[str, dict[str, Any]]] = {NO_WORKSPACE_SCOPE_ID: {}}
        result.update({workspace.workspace_id: {} for workspace in workspaces})
        if not isinstance(raw, dict):
            return result
        for workspace_id, items in raw.items():
            if workspace_id not in valid_ids and workspace_id != NO_WORKSPACE_SCOPE_ID:
                continue
            if not isinstance(items, dict):
                continue
            result[workspace_id] = {
                signature: note.to_dict()
                for signature, note in (
                    (signature, EntityNote.from_dict(payload))
                    for signature, payload in items.items()
                    if isinstance(signature, str) and isinstance(payload, dict)
                )
                if note.signature
            }
        return result

    def _normalized_audit(self, raw: Any, workspaces: list[Workspace]) -> dict[str, list[dict[str, Any]]]:
        valid_ids = {workspace.workspace_id for workspace in workspaces}
        result: dict[str, list[dict[str, Any]]] = {NO_WORKSPACE_SCOPE_ID: []}
        result.update({workspace.workspace_id: [] for workspace in workspaces})
        if not isinstance(raw, dict):
            return result
        for workspace_id, rows in raw.items():
            if workspace_id not in valid_ids and workspace_id != NO_WORKSPACE_SCOPE_ID:
                continue
            if not isinstance(rows, list):
                continue
            normalized_rows: list[dict[str, Any]] = []
            for entry in (AuditEntry.from_dict(item) for item in rows if isinstance(item, dict)):
                if workspace_id == NO_WORKSPACE_SCOPE_ID:
                    entry.workspace_id = ""
                elif not entry.workspace_id:
                    entry.workspace_id = workspace_id
                normalized_rows.append(entry.to_dict())
            result[workspace_id] = normalized_rows[-500:]
        return result

    def load_workspaces(self) -> list[Workspace]:
        payload = self._read_payload()
        if not _uses_workspace_model(payload):
            rows = payload.get("engagements", [])
            workspaces = [
                Workspace.from_dict(item)
                for item in rows
                if isinstance(item, dict) and str(item.get("engagement_id") or item.get("workspace_id") or "").strip()
            ]
            for workspace in workspaces:
                if not workspace.home_dir.strip():
                    workspace.home_dir = default_workspace_home(workspace.workspace_id)
            return workspaces
        rows = payload.get("workspaces", [])
        workspaces = [
            Workspace.from_dict(item)
            for item in rows
            if isinstance(item, dict) and str(item.get("workspace_id") or item.get("engagement_id") or "").strip()
        ]
        for workspace in workspaces:
            if not workspace.home_dir.strip():
                workspace.home_dir = default_workspace_home(workspace.workspace_id)
        return _prune_synthetic_default_workspaces(workspaces, payload)

    def save_workspace(self, workspace: Workspace) -> Path:
        payload = self._normalized_payload()
        workspaces = self.load_workspaces()
        workspace.updated_at = now_iso()
        if not workspace.created_at:
            workspace.created_at = workspace.updated_at
        if not workspace.home_dir.strip():
            workspace.home_dir = default_workspace_home(workspace.workspace_id)
        remaining = [item for item in workspaces if item.workspace_id != workspace.workspace_id]
        remaining.append(workspace)
        remaining.sort(key=lambda item: item.name.lower())
        payload["workspaces"] = [item.to_dict() for item in remaining]
        payload["run_registry"] = self._normalized_run_registry(payload.get("run_registry"), remaining)
        payload["finding_states"] = self._normalized_finding_states(payload.get("finding_states"), remaining)
        payload["entity_notes"] = self._normalized_entity_notes(payload.get("entity_notes"), remaining)
        payload["audit"] = self._normalized_audit(payload.get("audit"), remaining)
        if not str(payload.get("active_workspace_id") or ""):
            payload["active_workspace_id"] = workspace.workspace_id
        return self._write_payload(payload)

    def delete_workspace(self, workspace_id: str) -> Path:
        payload = self._normalized_payload()
        workspaces = [item for item in self.load_workspaces() if item.workspace_id != workspace_id]
        payload["workspaces"] = [item.to_dict() for item in workspaces]
        payload["run_registry"] = self._normalized_run_registry(payload.get("run_registry"), workspaces)
        payload["finding_states"] = self._normalized_finding_states(payload.get("finding_states"), workspaces)
        payload["entity_notes"] = self._normalized_entity_notes(payload.get("entity_notes"), workspaces)
        payload["audit"] = self._normalized_audit(payload.get("audit"), workspaces)
        if str(payload.get("active_workspace_id") or "") == workspace_id:
            payload["active_workspace_id"] = workspaces[0].workspace_id if workspaces else ""
        return self._write_payload(payload)

    def load_workspace(self, workspace_id: str) -> Workspace | None:
        for workspace in self.load_workspaces():
            if workspace.workspace_id == workspace_id:
                return workspace
        return None

    def get_active_workspace_id(self) -> str:
        payload = self._normalized_payload()
        return str(payload.get("active_workspace_id") or "")

    def get_active_workspace(self) -> Workspace | None:
        return self.load_workspace(self.get_active_workspace_id())

    def set_active_workspace(self, workspace_id: str) -> Path:
        payload = self._normalized_payload()
        payload["active_workspace_id"] = str(workspace_id or "")
        workspaces = self.load_workspaces()
        for workspace in workspaces:
            if workspace.workspace_id == workspace_id:
                workspace.last_opened_at = now_iso()
                workspace.updated_at = workspace.last_opened_at
        payload["workspaces"] = [workspace.to_dict() for workspace in workspaces]
        return self._write_payload(payload)

    def load_run_registry(self, workspace_id: str | None = None) -> list[RunRegistryEntry]:
        payload = self._normalized_payload()
        raw = payload.get("run_registry", {})
        if not isinstance(raw, dict):
            return []
        items = raw.get(self.scope_key(workspace_id), [])
        if not isinstance(items, list):
            return []
        return [RunRegistryEntry.from_dict(item) for item in items if isinstance(item, dict)]

    def save_run_registry(self, workspace_id: str | None, entries: list[RunRegistryEntry]) -> Path:
        payload = self._normalized_payload()
        run_registry = payload.setdefault("run_registry", {})
        if not isinstance(run_registry, dict):
            run_registry = {}
            payload["run_registry"] = run_registry
        scope_id = self.scope_key(workspace_id)
        rows: list[dict[str, Any]] = []
        for entry in entries:
            if not entry.run_id or not entry.run_dir:
                continue
            cloned = RunRegistryEntry.from_dict(entry.to_dict())
            if scope_id == NO_WORKSPACE_SCOPE_ID:
                cloned.workspace_id = ""
            elif not cloned.workspace_id:
                cloned.workspace_id = str(workspace_id or "")
            rows.append(cloned.to_dict())
        run_registry[scope_id] = rows
        return self._write_payload(payload)

    def register_run(self, entry: RunRegistryEntry) -> Path:
        entries = self.load_run_registry(entry.workspace_id)
        entry.last_seen_at = now_iso()
        remaining = [item for item in entries if item.run_id != entry.run_id]
        remaining.append(entry)
        remaining.sort(key=lambda item: (item.scan_name.lower(), item.run_id))
        return self.save_run_registry(entry.workspace_id, remaining)

    def update_run_entry(self, workspace_id: str | None, run_id: str, **updates: Any) -> Path:
        entries = self.load_run_registry(workspace_id)
        updated_entries: list[RunRegistryEntry] = []
        for entry in entries:
            if entry.run_id == run_id:
                for key, value in updates.items():
                    if hasattr(entry, key):
                        setattr(entry, key, value)
                entry.last_seen_at = now_iso()
            updated_entries.append(entry)
        return self.save_run_registry(workspace_id, updated_entries)

    def load_finding_states(self, workspace_id: str | None = None) -> dict[str, dict[str, FindingState]]:
        payload = self._read_payload()
        version = int(payload.get("version", 1) or 1)
        if version < LEGACY_WORKSPACE_STORE_VERSION and isinstance(payload.get("finding_states"), dict):
            raw = payload.get("finding_states", {})
            result: dict[str, dict[str, FindingState]] = {}
            for run_id, items in raw.items():
                if not isinstance(run_id, str) or not isinstance(items, dict):
                    continue
                result[run_id] = {
                    finding_id: FindingState.from_dict(state)
                    for finding_id, state in items.items()
                    if isinstance(finding_id, str) and isinstance(state, dict)
                }
            return result

        normalized = self._normalized_payload()
        raw = normalized.get("finding_states", {})
        if not isinstance(raw, dict):
            return {}
        if workspace_id is None:
            workspace_id = self.get_active_workspace_id()
        items = raw.get(self.scope_key(workspace_id), {})
        if not isinstance(items, dict):
            return {}
        result: dict[str, dict[str, FindingState]] = {}
        for run_id, states in items.items():
            if not isinstance(run_id, str) or not isinstance(states, dict):
                continue
            result[run_id] = {
                finding_id: FindingState.from_dict(payload)
                for finding_id, payload in states.items()
                if isinstance(finding_id, str) and isinstance(payload, dict)
            }
        return result

    def save_finding_state(self, *args: Any) -> Path:
        if len(args) == 2:
            workspace_id = self.get_active_workspace_id()
            run_id = str(args[0])
            state = args[1]
        elif len(args) == 3:
            workspace_id = str(args[0] or "")
            run_id = str(args[1])
            state = args[2]
        else:
            raise TypeError("save_finding_state expects (run_id, state) or (workspace_id, run_id, state)")
        if not isinstance(state, FindingState):
            raise TypeError("state must be a FindingState")
        payload = self._normalized_payload()
        states = payload.setdefault("finding_states", {})
        if not isinstance(states, dict):
            states = {}
            payload["finding_states"] = states
        workspace_states = states.setdefault(self.scope_key(workspace_id), {})
        if not isinstance(workspace_states, dict):
            workspace_states = {}
            states[self.scope_key(workspace_id)] = workspace_states
        run_states = workspace_states.setdefault(run_id, {})
        if not isinstance(run_states, dict):
            run_states = {}
            workspace_states[run_id] = run_states
        state.updated_at = now_iso()
        run_states[state.finding_id] = state.to_dict()
        return self._write_payload(payload)

    def load_entity_notes(self, workspace_id: str | None = None) -> dict[str, EntityNote]:
        normalized = self._normalized_payload()
        raw = normalized.get("entity_notes", {})
        if not isinstance(raw, dict):
            return {}
        if workspace_id is None:
            workspace_id = self.get_active_workspace_id()
        items = raw.get(self.scope_key(workspace_id), {})
        if not isinstance(items, dict):
            return {}
        return {
            signature: EntityNote.from_dict(payload)
            for signature, payload in items.items()
            if isinstance(signature, str) and isinstance(payload, dict)
        }

    def load_entity_note(self, signature: str, workspace_id: str | None = None) -> EntityNote | None:
        signature = str(signature or "").strip()
        if not signature:
            return None
        return self.load_entity_notes(workspace_id).get(signature)

    def save_entity_note(self, note: EntityNote, workspace_id: str | None = None) -> Path:
        if not isinstance(note, EntityNote):
            raise TypeError("note must be an EntityNote")
        signature = note.signature.strip()
        if not signature:
            raise ValueError("note signature is required")
        workspace_id = str(workspace_id or self.get_active_workspace_id() or "")
        payload = self._normalized_payload()
        notes = payload.setdefault("entity_notes", {})
        if not isinstance(notes, dict):
            notes = {}
            payload["entity_notes"] = notes
        scope_id = self.scope_key(workspace_id)
        workspace_notes = notes.setdefault(scope_id, {})
        if not isinstance(workspace_notes, dict):
            workspace_notes = {}
            notes[scope_id] = workspace_notes
        note.updated_at = now_iso()
        workspace_notes[signature] = note.to_dict()
        return self._write_payload(payload)

    def load_audit(self, workspace_id: str | None = None) -> list[AuditEntry]:
        payload = self._read_payload()
        version = int(payload.get("version", 1) or 1)
        if version < LEGACY_WORKSPACE_STORE_VERSION and isinstance(payload.get("audit"), list):
            return [AuditEntry.from_dict(item) for item in payload.get("audit", []) if isinstance(item, dict)]

        normalized = self._normalized_payload()
        raw = normalized.get("audit", {})
        if not isinstance(raw, dict):
            return []
        if workspace_id is None:
            workspace_id = self.get_active_workspace_id()
        rows = raw.get(self.scope_key(workspace_id), [])
        if not isinstance(rows, list):
            return []
        return [AuditEntry.from_dict(item) for item in rows if isinstance(item, dict)]

    def append_audit(self, entry: AuditEntry, workspace_id: str | None = None) -> Path:
        workspace_id = str(workspace_id or entry.workspace_id or self.get_active_workspace_id() or "")
        entry.workspace_id = workspace_id
        payload = self._normalized_payload()
        audit = payload.setdefault("audit", {})
        if not isinstance(audit, dict):
            audit = {}
            payload["audit"] = audit
        scope_id = self.scope_key(workspace_id)
        rows = audit.setdefault(scope_id, [])
        if not isinstance(rows, list):
            rows = []
            audit[scope_id] = rows
        payload_entry = AuditEntry.from_dict(entry.to_dict())
        if scope_id == NO_WORKSPACE_SCOPE_ID:
            payload_entry.workspace_id = ""
        rows.append(payload_entry.to_dict())
        audit[scope_id] = rows[-500:]
        return self._write_payload(payload)

    def load_ui_layout(self, layout_key: str, orientation: str | None = None) -> dict[str, list[int]] | list[int] | None:
        payload = self._normalized_payload()
        raw = payload.get("ui_layout", {})
        if not isinstance(raw, dict):
            return None
        layout = raw.get(str(layout_key or ""))
        if not isinstance(layout, dict):
            return None
        if orientation is None:
            return dict(layout)
        sizes = layout.get(str(orientation or ""))
        return list(sizes) if isinstance(sizes, list) else None

    def save_ui_layout(self, layout_key: str, orientation: str, sizes: list[int]) -> Path:
        payload = self._normalized_payload()
        ui_layout = payload.setdefault("ui_layout", {})
        if not isinstance(ui_layout, dict):
            ui_layout = {}
            payload["ui_layout"] = ui_layout
        key = str(layout_key or "").strip()
        if not key:
            return self._write_payload(payload)
        orientation_key = str(orientation or "").strip().lower()
        if orientation_key not in {"horizontal", "vertical"}:
            return self._write_payload(payload)
        normalized_sizes = [max(int(size), 0) for size in sizes if isinstance(size, (int, float))]
        if not normalized_sizes or not any(size > 0 for size in normalized_sizes):
            return self._write_payload(payload)
        layout = ui_layout.setdefault(key, {})
        if not isinstance(layout, dict):
            layout = {}
            ui_layout[key] = layout
        layout[orientation_key] = normalized_sizes
        return self._write_payload(payload)

    def apply_migration(
        self,
        *,
        workspaces: list[Workspace],
        active_workspace_id: str,
        run_registry: dict[str, list[RunRegistryEntry]],
        finding_states: dict[str, dict[str, dict[str, FindingState]]],
        audit: dict[str, list[AuditEntry]],
        import_roots: list[str],
    ) -> Path:
        payload = {
            "version": WORKSPACE_STORE_VERSION,
            "active_workspace_id": active_workspace_id,
            "workspaces": [workspace.to_dict() for workspace in workspaces],
            "run_registry": {
                workspace_id: [entry.to_dict() for entry in entries]
                for workspace_id, entries in run_registry.items()
            },
            "finding_states": {
                workspace_id: {
                    run_id: {finding_id: state.to_dict() for finding_id, state in run_states.items()}
                    for run_id, run_states in workspace_states.items()
                }
                for workspace_id, workspace_states in finding_states.items()
            },
            "entity_notes": {NO_WORKSPACE_SCOPE_ID: {}},
            "audit": {
                workspace_id: [entry.to_dict() for entry in rows[-500:]]
                for workspace_id, rows in audit.items()
            },
            "ui_layout": {},
            "migration_state": MigrationState(
                completed=True,
                import_roots=import_roots,
                last_detected_legacy_version=int(self._read_payload().get("version", 1) or 1),
            ).to_dict(),
        }
        return self._write_payload(payload)

    # Backward-compatible wrappers while older tests and helpers are updated.
    def load_engagements(self) -> list[Workspace]:
        return self.load_workspaces()

    def save_engagement(self, workspace: Workspace) -> Path:
        return self.save_workspace(workspace)

    def delete_engagement(self, engagement_id: str) -> Path:
        return self.delete_workspace(engagement_id)
