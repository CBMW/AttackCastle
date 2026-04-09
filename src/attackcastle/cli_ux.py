from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme


THEMES: dict[str, Theme] = {
    "professional": Theme(
        {
            "title": "bold cyan",
            "muted": "dim white",
            "ok": "green",
            "warn": "yellow",
            "err": "bold red",
            "accent": "bright_cyan",
            "badge": "bold black on #d9edf7",
        }
    ),
    "contrast": Theme(
        {
            "title": "bold white on black",
            "muted": "white",
            "ok": "bold green",
            "warn": "bold yellow",
            "err": "bold red",
            "accent": "bold cyan",
            "badge": "bold white on #444444",
        }
    ),
    "plain": Theme(
        {
            "title": "bold",
            "muted": "dim",
            "ok": "bold",
            "warn": "bold",
            "err": "bold",
            "accent": "bold",
            "badge": "bold",
        }
    ),
}


@dataclass
class UXConfig:
    ui_mode: str = "operator"
    theme: str = "professional"
    role: str = "operator"
    no_color: bool = False
    quiet: bool = False


def build_console(config: UXConfig, output_format: str) -> Console:
    machine_mode = output_format in {"json", "ndjson"} or config.ui_mode == "automation"
    no_color = config.no_color or machine_mode
    theme = THEMES.get(config.theme, THEMES["professional"])
    if no_color:
        theme = THEMES["plain"]
    return Console(
        theme=theme,
        no_color=no_color,
        soft_wrap=True,
        highlight=not no_color,
    )


def render_banner(console: Console, config: UXConfig) -> None:
    if config.ui_mode != "operator" or config.quiet:
        return
    title = "AttackCastle Operator Console"
    subtitle = f"mode={config.ui_mode} role={config.role} theme={config.theme}"
    panel = Panel.fit(f"[title]{title}[/title]\n[muted]{subtitle}[/muted]", border_style="accent")
    console.print(panel)


def render_next_steps(console: Console, steps: list[str]) -> None:
    if not steps:
        return
    table = Table(show_header=False, box=None, pad_edge=False)
    for idx, step in enumerate(steps, start=1):
        table.add_row(f"{idx}.", step)
    console.print(Panel.fit(table, title="Next Best Commands", border_style="accent"))


def render_safety_contract(console: Console, payload: dict[str, Any]) -> None:
    safety = payload.get("safety", {}) if isinstance(payload, dict) else {}
    orchestration = payload.get("orchestration", {}) if isinstance(payload, dict) else {}
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_row("max_hosts", str(safety.get("max_hosts")))
    table.add_row("hard_max_hosts", str(safety.get("hard_max_hosts")))
    table.add_row("max_ports", str(safety.get("max_ports")))
    table.add_row("hard_max_ports", str(safety.get("hard_max_ports")))
    table.add_row("max_total_retries", str(orchestration.get("max_total_retries")))
    table.add_row("retry_ceiling_by_capability", str(orchestration.get("retry_ceiling_by_capability", {})))
    console.print(Panel.fit(table, title="Safety Contract", border_style="warn"))


def render_operator_notice(console: Console, message: str, level: str = "muted") -> None:
    style_map = {"ok": "ok", "warn": "warn", "error": "err", "muted": "muted"}
    style = style_map.get(level, "muted")
    console.print(f"[{style}]{message}[/{style}]")


def render_task_graph(console: Console, items: list[dict[str, Any]]) -> None:
    table = Table(title="Workflow Graph", show_lines=False)
    table.add_column("Task")
    table.add_column("Depends On")
    table.add_column("Selected")
    table.add_column("Why")
    for item in items:
        deps = ", ".join(item.get("dependencies", []) or []) or "-"
        selected = "yes" if item.get("selected") else "no"
        table.add_row(str(item.get("key")), deps, selected, str(item.get("reason")))
    console.print(table)
