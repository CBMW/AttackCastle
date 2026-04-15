from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attackcastle.core.models import to_serializable


class RunStore:
    def __init__(self, output_root: Path, run_id: str, existing_run_dir: Path | None = None) -> None:
        self.output_root = output_root
        self.run_id = run_id
        self.run_dir = existing_run_dir or (self.output_root / f"run_{run_id}")
        self.data_dir = self.run_dir / "data"
        self.reports_dir = self.run_dir / "reports"
        self.artifacts_dir = self.run_dir / "artifacts"
        self.artifacts_raw_dir = self.artifacts_dir / "raw"
        self.logs_dir = self.run_dir / "logs"
        self.cache_dir = self.run_dir / "cache"
        self.checkpoints_dir = self.run_dir / "checkpoints"
        self.locks_dir = self.run_dir / "locks"
        self.control_dir = self.run_dir / "control"
        self.control_path = self.control_dir / "control.json"
        self._lock_path = self.locks_dir / ".run.lock"

        for path in (
            self.run_dir,
            self.data_dir,
            self.reports_dir,
            self.artifacts_dir,
            self.artifacts_raw_dir,
            self.logs_dir,
            self.cache_dir,
            self.checkpoints_dir,
            self.locks_dir,
            self.control_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

    @property
    def lock_path(self) -> Path:
        return self._lock_path

    @classmethod
    def from_existing(cls, run_dir: Path) -> "RunStore":
        resolved = run_dir.expanduser().resolve()
        output_root = resolved.parent
        run_id = resolved.name.replace("run_", "", 1)
        return cls(output_root=output_root, run_id=run_id, existing_run_dir=resolved)

    def acquire_lock(self) -> None:
        try:
            fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode("utf-8"))
            os.close(fd)
        except FileExistsError as exc:
            raise RuntimeError(
                f"Run directory is locked by another process: {self._lock_path}"
            ) from exc

    def release_lock(self) -> None:
        try:
            self._lock_path.unlink(missing_ok=True)
        except Exception:
            return

    def lock_exists(self) -> bool:
        return self._lock_path.exists()

    def lock_details(self) -> dict[str, Any]:
        if not self._lock_path.exists():
            return {"exists": False, "path": str(self._lock_path)}
        pid_text: str | None = None
        pid: int | None = None
        try:
            pid_text = self._lock_path.read_text(encoding="utf-8").strip()
            if pid_text:
                pid = int(pid_text)
        except Exception:
            pid = None

        mtime = datetime.fromtimestamp(self._lock_path.stat().st_mtime, tz=timezone.utc)
        age_seconds = max((datetime.now(timezone.utc) - mtime).total_seconds(), 0.0)
        process_alive = None
        if pid is not None:
            try:
                os.kill(pid, 0)
                process_alive = True
            except OSError:
                process_alive = False
            except Exception:
                process_alive = None

        return {
            "exists": True,
            "path": str(self._lock_path),
            "pid": pid,
            "pid_raw": pid_text,
            "age_seconds": age_seconds,
            "process_alive": process_alive,
        }

    def unlock_if_stale(self, max_age_minutes: int = 30) -> tuple[bool, str, dict[str, Any]]:
        details = self.lock_details()
        if not details.get("exists"):
            return False, "no_lock", details

        age_seconds = float(details.get("age_seconds", 0.0))
        max_age_seconds = float(max_age_minutes) * 60.0
        process_alive = details.get("process_alive")

        stale = age_seconds >= max_age_seconds or process_alive is False
        if not stale:
            return False, "lock_not_stale", details

        self.release_lock()
        details["removed"] = True
        return True, "unlocked", details

    def resolve(self, relative_path: str) -> Path:
        target = self._resolve_under(self.run_dir, relative_path, label="run path")
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def _resolve_under(self, base_dir: Path, relative_path: str, label: str) -> Path:
        if not relative_path or not relative_path.strip():
            raise ValueError(f"{label} must not be empty")
        candidate_path = Path(relative_path).expanduser()
        if candidate_path.is_absolute():
            raise ValueError(f"{label} must be relative to {base_dir}")
        resolved_base = base_dir.resolve()
        resolved_candidate = (resolved_base / candidate_path).resolve()
        try:
            resolved_candidate.relative_to(resolved_base)
        except ValueError as exc:
            raise ValueError(f"{label} must stay within {base_dir}") from exc
        return resolved_candidate

    def _atomic_write_bytes(self, path: Path, content: bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                delete=False,
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
            ) as handle:
                handle.write(content)
                temp_path = Path(handle.name)
            os.replace(temp_path, path)
            temp_path = None
            return path
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def write_json(self, relative_path: str, data: Any) -> Path:
        path = self.resolve(relative_path)
        content = json.dumps(to_serializable(data), indent=2, sort_keys=True).encode("utf-8")
        self._atomic_write_bytes(path, content)
        return path

    def read_json(self, relative_path: str) -> dict[str, Any]:
        path = self.resolve(relative_path)
        with path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        return loaded

    def write_text(self, relative_path: str, content: str) -> Path:
        path = self.resolve(relative_path)
        self._atomic_write_bytes(path, content.encode("utf-8"))
        return path

    def write_bytes(self, relative_path: str, content: bytes) -> Path:
        path = self.resolve(relative_path)
        self._atomic_write_bytes(path, content)
        return path

    def artifact_path(self, tool_name: str, file_name: str) -> Path:
        tool_dir = self._resolve_under(self.artifacts_raw_dir, tool_name, label="artifact tool name")
        tool_dir.mkdir(parents=True, exist_ok=True)
        return self._resolve_under(tool_dir, file_name, label="artifact file name")

    def log_path(self, file_name: str) -> Path:
        return self._resolve_under(self.logs_dir, file_name, label="log file name")

    @staticmethod
    def _safe_checkpoint_stem(task_key: str, instance_key: str | None = None) -> str:
        safe_task = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in task_key)[:80]
        if not instance_key:
            return safe_task or "checkpoint"
        digest = hashlib.sha1(instance_key.encode("utf-8")).hexdigest()[:12]  # noqa: S324
        return f"{safe_task or 'checkpoint'}__{digest}"

    @staticmethod
    def _manifest_entry_matches(item: dict[str, Any], task_key: str, instance_key: str | None) -> bool:
        if item.get("task_key") != task_key:
            return False
        existing_instance = item.get("instance_key")
        if instance_key:
            return existing_instance == instance_key
        return not isinstance(existing_instance, str) or not existing_instance.strip()

    def save_checkpoint(
        self,
        task_key: str,
        status: str,
        run_data: Any,
        *,
        instance_key: str | None = None,
        task_inputs: list[str] | tuple[str, ...] | None = None,
    ) -> Path:
        payload = {
            "task_key": task_key,
            "status": status,
            "run_data": to_serializable(run_data),
        }
        if instance_key:
            payload["instance_key"] = instance_key
            payload["task_inputs"] = list(task_inputs or [])
        checkpoint_path = self.checkpoints_dir / f"{self._safe_checkpoint_stem(task_key, instance_key)}.json"
        self._atomic_write_bytes(
            checkpoint_path,
            json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
        )

        manifest_path = self.checkpoints_dir / "manifest.json"
        manifest = self._read_checkpoint_manifest()
        checkpoints = [
            item
            for item in manifest["checkpoints"]
            if not self._manifest_entry_matches(item, task_key, instance_key)
        ]
        entry: dict[str, Any] = {
            "task_key": task_key,
            "status": status,
            "path": str(checkpoint_path),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        if instance_key:
            entry["instance_key"] = instance_key
            entry["task_inputs"] = list(task_inputs or [])
        checkpoints.append(entry)
        manifest["checkpoints"] = checkpoints
        self._atomic_write_bytes(
            manifest_path,
            json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"),
        )
        return checkpoint_path

    def load_latest_checkpoint(self) -> dict[str, Any] | None:
        checkpoints = self._read_checkpoint_manifest()["checkpoints"]
        for item in reversed(checkpoints):
            checkpoint_path_raw = item.get("path")
            if not isinstance(checkpoint_path_raw, str) or not checkpoint_path_raw.strip():
                continue
            checkpoint_path = Path(checkpoint_path_raw).expanduser()
            try:
                resolved_checkpoint_path = (
                    checkpoint_path.resolve()
                    if checkpoint_path.is_absolute()
                    else self._resolve_under(self.checkpoints_dir, checkpoint_path_raw, label="checkpoint path")
                )
                resolved_checkpoint_path.relative_to(self.checkpoints_dir.resolve())
            except (OSError, ValueError):
                continue
            if not resolved_checkpoint_path.exists() or not resolved_checkpoint_path.is_file():
                continue
            try:
                with resolved_checkpoint_path.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except Exception:
                continue
            if isinstance(payload, dict):
                return payload
        return None

    def list_completed_checkpoints(self) -> set[str]:
        completed = set()
        for item in self._read_checkpoint_manifest()["checkpoints"]:
            task_key = item.get("task_key")
            if not isinstance(task_key, str) or not task_key:
                continue
            instance_key = item.get("instance_key")
            if isinstance(instance_key, str) and instance_key.strip():
                continue
            if item.get("status") == "completed":
                completed.add(task_key)
        return completed

    def list_completed_checkpoint_instances(self) -> set[tuple[str, str]]:
        completed: set[tuple[str, str]] = set()
        for item in self._read_checkpoint_manifest()["checkpoints"]:
            task_key = item.get("task_key")
            instance_key = item.get("instance_key")
            if (
                item.get("status") == "completed"
                and isinstance(task_key, str)
                and task_key
                and isinstance(instance_key, str)
                and instance_key
            ):
                completed.add((task_key, instance_key))
        return completed

    def _read_checkpoint_manifest(self) -> dict[str, list[dict[str, Any]]]:
        manifest_path = self.checkpoints_dir / "manifest.json"
        if not manifest_path.exists():
            return {"checkpoints": []}
        try:
            with manifest_path.open("r", encoding="utf-8") as handle:
                loaded = json.load(handle)
        except Exception:
            return {"checkpoints": []}
        if not isinstance(loaded, dict):
            return {"checkpoints": []}
        checkpoints = loaded.get("checkpoints", [])
        if not isinstance(checkpoints, list):
            return {"checkpoints": []}
        sanitized = [item for item in checkpoints if isinstance(item, dict)]
        return {"checkpoints": sanitized}

    def _hash_file(self, path: Path) -> str:
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(8192)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

    def _iter_manifest_files(self) -> list[Path]:
        files: list[Path] = []
        for file_path in self.run_dir.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.name == "run_manifest.json":
                continue
            files.append(file_path)
        return sorted(files)

    def write_manifest(self, tool_version: str, schema_version: str) -> Path:
        files = self._iter_manifest_files()
        records = []
        for file_path in files:
            relative = file_path.relative_to(self.run_dir).as_posix()
            records.append(
                {
                    "path": relative,
                    "size": file_path.stat().st_size,
                    "sha256": self._hash_file(file_path),
                }
            )
        payload = {
            "run_id": self.run_id,
            "tool_version": tool_version,
            "schema_version": schema_version,
            "files": records,
        }
        return self.write_json("data/run_manifest.json", payload)

    def apply_retention(self, keep_raw_artifacts: bool = True) -> None:
        if keep_raw_artifacts:
            return
        if self.artifacts_raw_dir.exists():
            for file_path in self.artifacts_raw_dir.rglob("*"):
                if file_path.is_file():
                    file_path.unlink(missing_ok=True)

    def read_control(self) -> dict[str, Any] | None:
        if not self.control_path.exists():
            return None
        try:
            payload = json.loads(self.control_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        return payload

    def write_control(self, action: str, payload: dict[str, Any] | None = None) -> Path:
        body = {"action": action, **(payload or {})}
        self._atomic_write_bytes(
            self.control_path,
            json.dumps(to_serializable(body), indent=2, sort_keys=True).encode("utf-8"),
        )
        return self.control_path

    def clear_control(self) -> None:
        self.control_path.unlink(missing_ok=True)
