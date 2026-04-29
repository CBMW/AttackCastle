from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Callable

import psutil
from PySide6.QtCore import QProcess
from PySide6.QtWidgets import QWidget

from attackcastle.gui.models import ScanRequest
from attackcastle.gui.worker_protocol import WorkerEvent


class WorkerProcessManager:
    """Owns GUI worker process launch, stream buffering, and job-file cleanup."""

    def __init__(
        self,
        parent: QWidget,
        *,
        on_event: Callable[[QProcess, WorkerEvent], None],
        on_stderr: Callable[[str], None],
        on_finished: Callable[[QProcess, int, QProcess.ExitStatus], None],
    ) -> None:
        self._parent = parent
        self._on_event = on_event
        self._on_stderr = on_stderr
        self._on_finished = on_finished
        self.process_buffers: dict[QProcess, str] = {}
        self.job_files: dict[QProcess, Path] = {}
        self.process_run_ids: dict[QProcess, str] = {}
        self.run_processes: dict[str, QProcess] = {}

    def launch(self, request: ScanRequest) -> QProcess:
        job_handle = tempfile.NamedTemporaryFile(prefix="attackcastle-gui-job-", suffix=".json", delete=False)
        job_file = Path(job_handle.name)
        job_handle.close()
        job_file.write_text(json.dumps(request.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

        process = QProcess(self._parent)
        process.setProgram(sys.executable)
        process.setArguments(["-m", "attackcastle.gui.worker_main", str(job_file)])
        process.readyReadStandardOutput.connect(lambda p=process: self.read_stdout(p))
        process.readyReadStandardError.connect(lambda p=process: self.read_stderr(p))
        process.finished.connect(lambda code, status, p=process: self._on_finished(p, code, status))
        process.setProperty("workspace_id", request.workspace_id)
        self.process_buffers[process] = ""
        self.job_files[process] = job_file
        process.start()
        return process

    def read_stdout(self, process: QProcess) -> None:
        buffer = self.process_buffers.get(process, "")
        chunk = bytes(process.readAllStandardOutput()).decode("utf-8", errors="ignore")
        buffer += chunk
        lines = buffer.splitlines(keepends=False)
        if buffer and not buffer.endswith("\n"):
            self.process_buffers[process] = lines.pop() if lines else buffer
        else:
            self.process_buffers[process] = ""
        for line in lines:
            event = WorkerEvent.from_line(line)
            if event is not None:
                self._on_event(process, event)

    def read_stderr(self, process: QProcess) -> None:
        message = bytes(process.readAllStandardError()).decode("utf-8", errors="ignore").strip()
        if message:
            self._on_stderr(message)

    def mark_run_process(self, process: QProcess, run_id: str) -> None:
        self.process_run_ids[process] = run_id
        self.run_processes[run_id] = process

    def force_terminate_run(self, run_id: str) -> bool:
        process = self.run_processes.get(run_id)
        if process is None or process.state() == QProcess.NotRunning:
            return False
        pid = int(process.processId() or 0)
        if pid > 0:
            try:
                root = psutil.Process(pid)
                children = root.children(recursive=True)
                for child in children:
                    try:
                        child.kill()
                    except psutil.Error:
                        continue
                try:
                    root.kill()
                except psutil.Error:
                    pass
                psutil.wait_procs([*children, root], timeout=2)
            except psutil.Error:
                process.kill()
        else:
            process.kill()
        return True

    def cleanup(self, process: QProcess) -> tuple[Path | None, str]:
        job_file = self.job_files.pop(process, None)
        self.process_buffers.pop(process, None)
        run_id = self.process_run_ids.pop(process, "")
        if run_id:
            self.run_processes.pop(run_id, None)
        if job_file is not None:
            job_file.unlink(missing_ok=True)
        return job_file, run_id
