from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from attackcastle.app import ScanOutcome
from attackcastle.cli_ux import UXConfig, build_console


class CliRuntime:
    """Shared CLI concerns kept separate from Typer command registration."""

    def ux(self, ctx: typer.Context | None) -> UXConfig:
        if ctx is None:
            return UXConfig()
        value = getattr(ctx, "obj", None)
        if isinstance(value, UXConfig):
            return value
        if isinstance(value, dict):
            return UXConfig(
                interactive=bool(value.get("interactive", False)),
                show_help=bool(value.get("show_help", False)),
            )
        return UXConfig()

    def console(self, ctx: typer.Context | None, output_format: str) -> Console:
        return build_console(self.ux(ctx), output_format=output_format)

    def emit_payload(self, console: Console, payload: dict[str, Any], output_format: str, event: str = "result") -> None:
        if output_format == "json":
            console.print_json(data={"event": event, **payload})
        else:
            console.print(payload)

    def exit_with_error(
        self,
        console: Console,
        message: str,
        *,
        output_format: str = "text",
        code: int = 1,
        event: str = "error",
    ) -> None:
        if output_format == "json":
            self.emit_payload(console, {"message": message, "exit_code": code}, output_format, event=event)
        else:
            console.print(f"[red]{message}[/red]")
        raise typer.Exit(code)

    def exit_code_for_outcome(self, outcome: ScanOutcome) -> int:
        if outcome.error_count:
            return 2
        if outcome.warning_count:
            return 1
        return 0

    def resolve_run_dir(self, value: str) -> Path:
        return Path(value).expanduser().resolve()
