import sys
from pathlib import Path

from attackcastle.adapters.command_runner import CommandSpec, run_command_spec
from attackcastle.core.interfaces import AdapterContext
from attackcastle.storage.run_store import RunStore


class _Audit:
    def write(self, event, payload):  # noqa: ANN001, D401
        return None


def _context(tmp_path: Path) -> AdapterContext:
    run_store = RunStore(output_root=tmp_path, run_id="command-runner")
    return AdapterContext(
        profile_name="test",
        config={},
        profile_config={},
        run_store=run_store,
        logger=None,
        audit=_Audit(),
    )


def test_run_command_spec_captures_transcript_and_completion_metadata(tmp_path: Path) -> None:
    context = _context(tmp_path)

    result = run_command_spec(
        context,
        CommandSpec(
            tool_name="python",
            capability="unit_test",
            task_type="ExampleCommand",
            command=[
                sys.executable,
                "-c",
                "import sys; print('hello', flush=True); print('oops', file=sys.stderr, flush=True)",
            ],
            timeout_seconds=5,
            artifact_prefix="example",
        ),
    )

    transcript_path = result.transcript_path
    assert transcript_path.exists()
    transcript_text = transcript_path.read_text(encoding="utf-8")
    assert "hello" in transcript_text
    assert "oops" in transcript_text
    assert result.execution.termination_reason == "completed"
    assert result.execution.termination_detail is None
    assert result.execution.transcript_path == str(transcript_path)
    assert result.task_result.transcript_path == str(transcript_path)
    assert result.task_result.termination_reason == "completed"


def test_run_command_spec_timeout_sets_explicit_termination_metadata(tmp_path: Path) -> None:
    context = _context(tmp_path)

    result = run_command_spec(
        context,
        CommandSpec(
            tool_name="python",
            capability="unit_test",
            task_type="TimeoutCommand",
            command=[
                sys.executable,
                "-c",
                "import sys,time; print('before-timeout', flush=True); sys.stderr.write('waiting\\n'); sys.stderr.flush(); time.sleep(2)",
            ],
            timeout_seconds=1,
            artifact_prefix="timeout",
        ),
    )

    transcript_text = result.transcript_path.read_text(encoding="utf-8")
    assert "before-timeout" in transcript_text
    assert "waiting" in transcript_text
    assert result.execution.status == "failed"
    assert result.execution.termination_reason == "timeout"
    assert result.execution.timed_out is True
    assert "timeout" in str(result.execution.termination_detail).lower()
    assert result.task_result.termination_reason == "timeout"
    assert result.task_result.timed_out is True


def test_run_command_spec_missing_tool_sets_missing_dependency_metadata(tmp_path: Path) -> None:
    context = _context(tmp_path)

    result = run_command_spec(
        context,
        CommandSpec(
            tool_name="missing-tool",
            capability="unit_test",
            task_type="MissingToolCommand",
            command=["attackcastle-definitely-missing-tool"],
            timeout_seconds=1,
            artifact_prefix="missing",
        ),
    )

    assert result.execution.status == "skipped"
    assert result.execution.termination_reason == "missing_dependency"
    assert "missing required tool" in str(result.execution.termination_detail)
    assert result.task_result.termination_reason == "missing_dependency"
