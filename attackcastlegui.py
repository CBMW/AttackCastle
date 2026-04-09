#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RUNTIME_DIR = ROOT / ".attackcastle-runtime"
BOOTSTRAP_STATE_PATH = RUNTIME_DIR / "bootstrap_state.json"
TOOL_CHECK_CACHE_PATH = RUNTIME_DIR / "tool_check_cache.json"
MINIMUM_PYTHON = (3, 12)
BOOTSTRAP_STATE_VERSION = 1
TOOL_CHECK_CACHE_VERSION = 1
TOOL_CHECK_CACHE_TTL_SECONDS = 600


IMPORT_CHECK_SNIPPET = """
import importlib
import sys

missing = []
for module_name in (
    "attackcastle.gui.launcher",
    "PySide6",
    "rich",
    "typer",
    "jinja2",
    "yaml",
    "jsonschema",
):
    try:
        importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001
        missing.append(f"{module_name}: {exc}")

if missing:
    sys.stderr.write("\\n".join(missing) + "\\n")
    raise SystemExit(1)
"""


TOOL_CHECK_SNIPPET = """
import json
from attackcastle.readiness import external_dependency_rows, missing_dependency_rows

rows = external_dependency_rows()
print(json.dumps({"rows": rows, "missing": missing_dependency_rows(rows)}))
"""


def _status(message: str) -> None:
    print(f"[attackcastlegui] {message}")


def _fail(message: str, *, detail: str | None = None, code: int = 1) -> int:
    sys.stderr.write(f"[attackcastlegui] {message}\n")
    if detail:
        sys.stderr.write(f"{detail.rstrip()}\n")
    return code


def _python_version_label(version_info: tuple[int, ...] | tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version_info[:3])


def _runtime_python_path() -> Path:
    if os.name == "nt":
        return RUNTIME_DIR / "Scripts" / "python.exe"
    return RUNTIME_DIR / "bin" / "python3"


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd or ROOT),
        text=True,
        capture_output=capture,
        check=False,
    )


def _bootstrap_state() -> dict[str, object]:
    pyproject_path = ROOT / "pyproject.toml"
    return {
        "state_version": BOOTSTRAP_STATE_VERSION,
        "python_version": list(sys.version_info[:3]),
        "pyproject_mtime_ns": pyproject_path.stat().st_mtime_ns if pyproject_path.exists() else 0,
    }


def _load_bootstrap_state() -> dict[str, object]:
    if not BOOTSTRAP_STATE_PATH.exists():
        return {}
    try:
        payload = json.loads(BOOTSTRAP_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_bootstrap_state() -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    BOOTSTRAP_STATE_PATH.write_text(json.dumps(_bootstrap_state(), indent=2, sort_keys=True), encoding="utf-8")


def _ensure_supported_python() -> int:
    current = sys.version_info[:3]
    if current >= MINIMUM_PYTHON:
        return 0
    return _fail(
        f"Python {_python_version_label(current)} is too old.",
        detail=(
            f"AttackCastle requires Python {_python_version_label(MINIMUM_PYTHON + (0,))} or newer.\n"
            "Install a newer Python and rerun `python3 attackcastlegui.py`."
        ),
    )


def _ensure_runtime_exists() -> int:
    runtime_python = _runtime_python_path()
    if runtime_python.exists():
        return 0

    _status(f"Creating local runtime in {RUNTIME_DIR}")
    result = _run([sys.executable, "-m", "venv", str(RUNTIME_DIR)], capture=True)
    if result.returncode == 0 and runtime_python.exists():
        return 0

    detail_parts = []
    if result.stderr.strip():
        detail_parts.append(result.stderr.strip())
    if result.stdout.strip():
        detail_parts.append(result.stdout.strip())
    detail_parts.append(
        "Install the Python venv support package first, for example `sudo apt install python3-venv`, then rerun this launcher."
    )
    return _fail("Could not create the local AttackCastle runtime.", detail="\n".join(detail_parts))


def _runtime_imports_ready(runtime_python: Path) -> bool:
    result = _run([str(runtime_python), "-c", IMPORT_CHECK_SNIPPET], capture=True)
    return result.returncode == 0


def _ensure_runtime_packages(runtime_python: Path, *, force: bool = False, verify: bool = False) -> int:
    state_matches = _load_bootstrap_state() == _bootstrap_state()
    if not force and state_matches and not verify:
        return 0
    if not force and state_matches and verify and _runtime_imports_ready(runtime_python):
        return 0

    _status("Installing/updating AttackCastle GUI dependencies in the local runtime")
    pip_upgrade = _run([str(runtime_python), "-m", "pip", "install", "--upgrade", "pip"], capture=True)
    if pip_upgrade.returncode != 0:
        return _fail("Could not upgrade pip in the local runtime.", detail=pip_upgrade.stderr or pip_upgrade.stdout)

    install = _run([str(runtime_python), "-m", "pip", "install", "--editable", ".[gui]"], capture=True)
    if install.returncode != 0:
        return _fail("Could not install AttackCastle GUI dependencies.", detail=install.stderr or install.stdout)

    if not _runtime_imports_ready(runtime_python):
        return _fail("AttackCastle dependencies still failed to import after installation.")

    _write_bootstrap_state()
    return 0


def _tool_check_cache_state() -> dict[str, object]:
    path_hash = hashlib.sha256(os.environ.get("PATH", "").encode("utf-8")).hexdigest()
    return {
        "cache_version": TOOL_CHECK_CACHE_VERSION,
        "path_hash": path_hash,
    }


def _load_tool_check_cache() -> dict[str, object]:
    if not TOOL_CHECK_CACHE_PATH.exists():
        return {}
    try:
        payload = json.loads(TOOL_CHECK_CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_tool_check_cache(missing: list[object]) -> None:
    payload = {
        **_tool_check_cache_state(),
        "checked_at": int(time.time()),
        "missing": missing,
    }
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    TOOL_CHECK_CACHE_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _cached_missing_tool_rows() -> list[object] | None:
    payload = _load_tool_check_cache()
    if not payload:
        return None
    if payload.get("cache_version") != TOOL_CHECK_CACHE_VERSION:
        return None
    if payload.get("path_hash") != _tool_check_cache_state()["path_hash"]:
        return None
    checked_at = payload.get("checked_at")
    if not isinstance(checked_at, int):
        return None
    if time.time() - checked_at > TOOL_CHECK_CACHE_TTL_SECONDS:
        return None
    missing = payload.get("missing")
    return missing if isinstance(missing, list) else None


def _print_missing_tool_rows(missing: list[object]) -> None:
    for row in missing:
        if not isinstance(row, dict):
            continue
        command = str(row.get("command") or "unknown")
        apt_package = str(row.get("apt_package") or "")
        suggestion = str(row.get("suggestion") or "")
        package_hint = f" | apt: {apt_package}" if apt_package else ""
        suffix = f" | {suggestion}" if suggestion else ""
        print(f"  - {command}{package_hint}{suffix}")


def _check_tools(runtime_python: Path, *, refresh: bool = False) -> int:
    if not refresh:
        cached_missing = _cached_missing_tool_rows()
        if cached_missing is not None:
            if cached_missing:
                _status(
                    "Tool check: using cached result. Some external scanner tools are still missing. "
                    "Run with --refresh-tool-check to rescan now."
                )
            else:
                _status("Tool check: using cached result. All configured external scanner tools were found.")
            return 0

    result = _run([str(runtime_python), "-c", TOOL_CHECK_SNIPPET], capture=True)
    if result.returncode != 0:
        return _fail("Could not complete the external tool readiness check.", detail=result.stderr or result.stdout)

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return _fail("Tool readiness check returned invalid output.", detail=result.stdout)

    missing = payload.get("missing", [])
    if not isinstance(missing, list):
        missing = []
    _write_tool_check_cache(missing)
    if not missing:
        _status("Tool check: all configured external scanner tools were found.")
        return 0

    _status("Tool check: some external scanner tools are missing. The GUI can still launch, but coverage will be reduced.")
    _print_missing_tool_rows(missing)
    return 0


def _launch_gui(runtime_python: Path) -> int:
    _status("Launching AttackCastle GUI")
    launch = subprocess.run([str(runtime_python), "-m", "attackcastle.gui.launcher"], cwd=str(ROOT), check=False)
    return int(launch.returncode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bootstrap and launch the AttackCastle GUI without manual virtualenv steps.",
    )
    parser.add_argument(
        "--skip-tool-check",
        action="store_true",
        help="Launch the GUI without checking external scanner tools first.",
    )
    parser.add_argument(
        "--rebuild-runtime",
        action="store_true",
        help="Force a dependency reinstall in the private local runtime before launch.",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Run runtime and tool checks, then exit without launching the GUI.",
    )
    parser.add_argument(
        "--refresh-tool-check",
        action="store_true",
        help="Force a fresh external tool scan instead of using the cached result.",
    )
    args = parser.parse_args(argv)

    python_check = _ensure_supported_python()
    if python_check:
        return python_check

    runtime_check = _ensure_runtime_exists()
    if runtime_check:
        return runtime_check

    runtime_python = _runtime_python_path()
    package_check = _ensure_runtime_packages(
        runtime_python,
        force=args.rebuild_runtime,
        verify=args.check_only,
    )
    if package_check:
        return package_check

    if not args.skip_tool_check:
        tool_check = _check_tools(runtime_python, refresh=args.refresh_tool_check)
        if tool_check:
            return tool_check

    if args.check_only:
        _status("Checks completed. GUI launch skipped by --check-only.")
        return 0

    return _launch_gui(runtime_python)


if __name__ == "__main__":
    raise SystemExit(main())
