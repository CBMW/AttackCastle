from __future__ import annotations

import json
from pathlib import Path

import pytest

from attackcastle.tools.library import ToolLibraryStore


def _tool(tool_id: str, *, name: str | None = None, scope: str = "global", enabled: bool = True) -> dict[str, object]:
    return {
        "id": tool_id,
        "display_name": name or tool_id.title(),
        "category": "utility",
        "platforms": ["linux", "windows", "darwin"],
        "enabled": enabled,
        "executable_name": tool_id,
        "detection_command": f"{tool_id} --version",
        "timeout_seconds": 30,
        "save_scope": scope,
    }


def test_tool_library_loads_layered_definitions_by_precedence(tmp_path: Path) -> None:
    builtin = tmp_path / "builtin"
    global_dir = tmp_path / "global"
    profile_dir = tmp_path / "profile"
    workspace_home = tmp_path / "workspace"
    workspace_dir = workspace_home / ".attackcastle" / "tools"
    for path in (builtin, global_dir, profile_dir, workspace_dir):
        path.mkdir(parents=True)
    (builtin / "nmap.json").write_text(json.dumps(_tool("nmap", name="Built-in Nmap")), encoding="utf-8")
    (global_dir / "nmap.json").write_text(json.dumps(_tool("nmap", name="Global Nmap")), encoding="utf-8")
    (profile_dir / "nmap.json").write_text(json.dumps(_tool("nmap", name="Profile Nmap")), encoding="utf-8")
    (workspace_dir / "nmap.json").write_text(json.dumps(_tool("nmap", name="Workspace Nmap", scope="workspace")), encoding="utf-8")

    store = ToolLibraryStore(
        builtin_dir=builtin,
        global_dir=global_dir,
        profile_name_provider=lambda: "ignored",
        workspace_home_provider=lambda: str(workspace_home),
    )
    store.profile_dir = lambda: profile_dir  # type: ignore[method-assign]

    result = store.load_definitions()

    assert result.warnings == []
    assert len(result.definitions) == 1
    assert result.definitions[0]["display_name"] == "Workspace Nmap"
    assert result.definitions[0]["metadata"]["source"] == "workspace"


def test_tool_library_validates_blank_ids(tmp_path: Path) -> None:
    store = ToolLibraryStore(builtin_dir=tmp_path / "builtin", global_dir=tmp_path / "global")

    with pytest.raises(ValueError, match="tool id is required"):
        store.save_definition({"id": "", "display_name": "Broken", "executable_name": "broken"})


def test_tool_library_saves_to_requested_scope(tmp_path: Path) -> None:
    workspace_home = tmp_path / "workspace"
    store = ToolLibraryStore(
        builtin_dir=tmp_path / "builtin",
        global_dir=tmp_path / "global",
        workspace_home_provider=lambda: str(workspace_home),
    )

    path = store.save_definition(_tool("custom", scope="workspace"))

    assert path == workspace_home / ".attackcastle" / "tools" / "custom.json"
    assert json.loads(path.read_text(encoding="utf-8"))["save_scope"] == "workspace"


def test_tool_library_duplicate_creates_unique_id_and_file(tmp_path: Path) -> None:
    store = ToolLibraryStore(builtin_dir=tmp_path / "builtin", global_dir=tmp_path / "global")
    store.save_definition(_tool("custom"))

    duplicate = store.duplicate_definition(_tool("custom"))

    assert duplicate["id"] == "custom-copy"
    assert (tmp_path / "global" / "custom-copy.json").exists()
