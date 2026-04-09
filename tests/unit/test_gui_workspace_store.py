from __future__ import annotations

from pathlib import Path

import json

from attackcastle.gui.models import (
    AuditEntry,
    Engagement,
    EntityNote,
    FindingState,
    OverviewChecklistItem,
    RunRegistryEntry,
    WorkspaceOverviewState,
)
from attackcastle.gui.workspace_store import NO_WORKSPACE_SCOPE_ID, WorkspaceStore


def test_workspace_store_starts_with_no_saved_workspaces(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "workspace.json")
    engagements = store.load_engagements()
    assert engagements == []
    assert store.get_active_workspace_id() == ""


def test_workspace_store_round_trip(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "workspace.json")
    engagement = Engagement(engagement_id="eng_1", name="Client Alpha", client_name="Alpha")
    store.save_engagement(engagement)
    store.save_finding_state("run_1", FindingState(finding_id="finding_1", status="confirmed"))
    store.append_audit(AuditEntry(timestamp="2026-03-15T00:00:00+00:00", action="test", summary="saved"))

    engagements = store.load_engagements()
    states = store.load_finding_states()
    audit = store.load_audit()

    assert any(item.engagement_id == "eng_1" for item in engagements)
    assert states["run_1"]["finding_1"].status == "confirmed"
    assert audit[-1].action == "test"


def test_workspace_store_recovers_from_invalid_json(tmp_path: Path) -> None:
    store_path = tmp_path / "workspace.json"
    store_path.write_text("{not valid json", encoding="utf-8")

    store = WorkspaceStore(store_path)

    engagements = store.load_engagements()
    states = store.load_finding_states()
    audit = store.load_audit()

    assert engagements == []
    assert states == {}
    assert audit == []


def test_workspace_store_recovers_from_non_object_payload(tmp_path: Path) -> None:
    store_path = tmp_path / "workspace.json"
    store_path.write_text('["bad"]', encoding="utf-8")

    store = WorkspaceStore(store_path)
    store.save_finding_state("run_1", FindingState(finding_id="finding_1", status="confirmed"))

    payload = json.loads(store_path.read_text(encoding="utf-8"))

    assert payload["version"] == 5
    assert isinstance(payload["workspaces"], list)
    assert payload["active_workspace_id"] == ""
    assert payload["finding_states"][NO_WORKSPACE_SCOPE_ID]["run_1"]["finding_1"]["status"] == "confirmed"
    assert payload["ui_layout"] == {}


def test_workspace_store_ignores_invalid_engagement_rows(tmp_path: Path) -> None:
    store_path = tmp_path / "workspace.json"
    store_path.write_text(
        json.dumps(
            {
                "version": 1,
                "engagements": [
                    {"engagement_id": "", "name": "Missing Id"},
                    {"engagement_id": "eng_valid", "name": "Valid Engagement"},
                    {"name": "Missing Id Entirely"},
                ],
                "finding_states": {},
                "audit": [],
            }
        ),
        encoding="utf-8",
    )

    engagements = WorkspaceStore(store_path).load_engagements()

    assert [item.engagement_id for item in engagements] == ["eng_valid"]


def test_workspace_store_uses_internal_scope_for_no_workspace_data(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "workspace.json")

    store.save_finding_state("run_1", FindingState(finding_id="finding_1", status="confirmed"))
    store.append_audit(AuditEntry(timestamp="2026-03-15T00:00:00+00:00", action="ad_hoc", summary="saved"))

    payload = json.loads(store.path.read_text(encoding="utf-8"))

    assert payload["finding_states"][NO_WORKSPACE_SCOPE_ID]["run_1"]["finding_1"]["status"] == "confirmed"
    assert payload["audit"][NO_WORKSPACE_SCOPE_ID][-1]["action"] == "ad_hoc"
    assert payload["audit"][NO_WORKSPACE_SCOPE_ID][-1]["workspace_id"] == ""


def test_workspace_store_round_trips_workspace_scoped_entity_notes(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "workspace.json")
    store.save_engagement(Engagement(engagement_id="eng_1", name="Client Alpha"))

    note = EntityNote(signature="asset|host|example.com|203.0.113.10|", entity_kind="asset", label="example.com", note="Crown jewel")
    store.save_entity_note(note, "eng_1")

    loaded = store.load_entity_notes("eng_1")

    assert loaded["asset|host|example.com|203.0.113.10|"].note == "Crown jewel"
    assert loaded["asset|host|example.com|203.0.113.10|"].entity_kind == "asset"


def test_workspace_store_round_trips_workspace_overview_state(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "workspace.json")
    store.save_engagement(Engagement(engagement_id="eng_1", name="Client Alpha"))

    state = WorkspaceOverviewState(
        checklist_items=[
            OverviewChecklistItem(
                item_id="item-1",
                label="Validate root scope",
                completed=True,
                created_at="2026-04-09T00:00:00+00:00",
                updated_at="2026-04-09T00:10:00+00:00",
            )
        ],
        notes="Operator note",
    )
    store.save_overview_state("eng_1", state)

    loaded = store.load_overview_state("eng_1")

    assert loaded.notes == "Operator note"
    assert len(loaded.checklist_items) == 1
    assert loaded.checklist_items[0].label == "Validate root scope"
    assert loaded.checklist_items[0].completed is True


def test_workspace_store_upgrades_v4_payload_without_losing_data(tmp_path: Path) -> None:
    store_path = tmp_path / "workspace.json"
    store_path.write_text(
        json.dumps(
            {
                "version": 4,
                "active_workspace_id": "eng_1",
                "workspaces": [{"workspace_id": "eng_1", "name": "Client Alpha"}],
                "run_registry": {NO_WORKSPACE_SCOPE_ID: [], "eng_1": []},
                "finding_states": {NO_WORKSPACE_SCOPE_ID: {}, "eng_1": {}},
                "entity_notes": {NO_WORKSPACE_SCOPE_ID: {}, "eng_1": {}},
                "audit": {NO_WORKSPACE_SCOPE_ID: [], "eng_1": []},
                "ui_layout": {},
                "migration_state": {"completed": True},
            }
        ),
        encoding="utf-8",
    )
    store = WorkspaceStore(store_path)

    store.save_entity_note(EntityNote(signature="sig", entity_kind="asset", note="Tracked"), "eng_1")

    payload = json.loads(store_path.read_text(encoding="utf-8"))
    assert payload["version"] == 5
    assert payload["workspaces"][0]["workspace_id"] == "eng_1"
    assert payload["entity_notes"]["eng_1"]["sig"]["note"] == "Tracked"
    assert payload["overview_state"] == {}


def test_workspace_store_round_trips_ui_layout_by_key_and_orientation(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "workspace.json")

    store.save_ui_layout("body_split", "horizontal", [240, 1180])
    store.save_ui_layout("body_split", "vertical", [220, 840])

    assert store.load_ui_layout("body_split", "horizontal") == [240, 1180]
    assert store.load_ui_layout("body_split", "vertical") == [220, 840]

    payload = json.loads(store.path.read_text(encoding="utf-8"))
    assert payload["ui_layout"]["body_split"]["horizontal"] == [240, 1180]
    assert payload["ui_layout"]["body_split"]["vertical"] == [220, 840]


def test_delete_workspaces_prunes_all_workspace_scoped_state(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "workspace.json")
    store.save_engagement(Engagement(engagement_id="eng_alpha", name="Alpha"))
    store.save_engagement(Engagement(engagement_id="eng_beta", name="Beta"))
    store.set_active_workspace("eng_alpha")
    store.register_run(RunRegistryEntry(run_id="run-alpha", run_dir=str(tmp_path / "alpha-run"), workspace_id="eng_alpha"))
    store.save_finding_state("eng_alpha", "run-alpha", FindingState(finding_id="finding-alpha", status="confirmed"))
    store.save_entity_note(EntityNote(signature="sig-alpha", entity_kind="asset", note="keep out"), "eng_alpha")
    store.append_audit(AuditEntry(timestamp="2026-04-09T00:00:00+00:00", action="workspace.note", summary="alpha", workspace_id="eng_alpha"))
    store.save_overview_state("eng_alpha", WorkspaceOverviewState(notes="alpha notes"))
    store.save_finding_state("", "run-ad-hoc", FindingState(finding_id="finding-ad-hoc", status="confirmed"))

    store.delete_workspaces(["eng_alpha"])

    payload = json.loads(store.path.read_text(encoding="utf-8"))
    assert [workspace["workspace_id"] for workspace in payload["workspaces"]] == ["eng_beta"]
    assert payload["active_workspace_id"] == "eng_beta"
    assert "eng_alpha" not in payload["run_registry"]
    assert "eng_alpha" not in payload["finding_states"]
    assert "eng_alpha" not in payload["entity_notes"]
    assert "eng_alpha" not in payload["audit"]
    assert "eng_alpha" not in payload["overview_state"]
    assert payload["finding_states"][NO_WORKSPACE_SCOPE_ID]["run-ad-hoc"]["finding-ad-hoc"]["status"] == "confirmed"


def test_delete_all_workspaces_clears_workspace_registry_but_preserves_ad_hoc_scope(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "workspace.json")
    store.save_engagement(Engagement(engagement_id="eng_alpha", name="Alpha"))
    store.save_engagement(Engagement(engagement_id="eng_beta", name="Beta"))
    store.register_run(RunRegistryEntry(run_id="run-beta", run_dir=str(tmp_path / "beta-run"), workspace_id="eng_beta"))
    store.append_audit(AuditEntry(timestamp="2026-04-09T00:00:00+00:00", action="workspace.note", summary="beta", workspace_id="eng_beta"))
    store.save_finding_state("", "run-ad-hoc", FindingState(finding_id="finding-ad-hoc", status="confirmed"))

    store.delete_all_workspaces()

    payload = json.loads(store.path.read_text(encoding="utf-8"))
    assert payload["workspaces"] == []
    assert payload["active_workspace_id"] == ""
    assert payload["run_registry"] == {NO_WORKSPACE_SCOPE_ID: []}
    assert payload["audit"] == {NO_WORKSPACE_SCOPE_ID: []}
    assert payload["finding_states"][NO_WORKSPACE_SCOPE_ID]["run-ad-hoc"]["finding-ad-hoc"]["status"] == "confirmed"
