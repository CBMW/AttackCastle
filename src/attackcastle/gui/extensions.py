from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema

EXTENSION_SCHEMA_VERSION = "extensions/v1"
LEGACY_DEFAULT_THEME_EXTENSION_ID = "attackcastle-default-theme"
DEFAULT_THEME_EXTENSION_ID = "attackcastle-graphite-modern"
DEFAULT_THEME_EXTENSION_NAME = "AttackCastle Graphite Modern"
DEFAULT_THEME_EXTENSION_DESCRIPTION = (
    "Modern graphite AttackCastle theme with premium blue-violet accents and cleaner contrast."
)


class ExtensionValidationError(ValueError):
    """Raised when an extension manifest fails schema or semantic validation."""


EXTENSION_MANIFEST_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["schema_version", "id", "name", "version", "capabilities"],
    "properties": {
        "schema_version": {"type": "string", "const": EXTENSION_SCHEMA_VERSION},
        "id": {"type": "string", "minLength": 1},
        "name": {"type": "string", "minLength": 1},
        "version": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "capabilities": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string", "enum": ["theme", "command_hook", "report"]},
            "uniqueItems": True,
        },
        "theme": {
            "type": "object",
            "properties": {
                "tokens": {"type": "object"},
                "qss_append": {"type": "string"},
            },
            "required": ["tokens"],
            "additionalProperties": False,
        },
        "command_hook": {
            "type": "object",
            "properties": {
                "hook": {"type": "string", "enum": ["pre_report"]},
                "command": {"type": "string", "minLength": 1},
                "args": {"type": "array", "items": {"type": "string"}},
                "timeout_seconds": {"type": "integer", "minimum": 1},
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["hook", "command"],
            "additionalProperties": False,
        },
        "report": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "notes": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": False,
}


DEFAULT_THEME_TOKENS: dict[str, Any] = {
    "gradients": {
        "app_shell": {
            "start": "#111318",
            "mid": "#0b0e13",
            "end": "#07090d",
        },
        "panel": {
            "start": "#161c25",
            "mid": "#111722",
            "end": "#0b1017",
        },
        "summary_accent": {
            "start": "#6f9bff",
            "mid": "#4f86ff",
            "end": "#58d4ff",
        },
        "surface": {
            "start": "#141a23",
            "end": "#0d1219",
        },
    },
    "palette": {
        "accent_border": "#73a2ff",
        "accent_primary": "#78a6ff",
        "accent_secondary": "#4e84ff",
        "accent_soft": "#68d1ff",
        "border": "#2b3747",
        "border_soft": "#1e2834",
        "chip_bg": "#101720",
        "chip_hover": "#172130",
        "hero_end": "#07090d",
        "hero_glow": "#131b27",
        "hero_mid": "#0b1016",
        "input_bg": "#0c1219",
        "panel_top": "#171e28",
        "panel_mid": "#111722",
        "panel_bottom": "#0b1017",
        "progress_start": "#4ade80",
        "progress_mid": "#5a8eff",
        "progress_end": "#5fd8ff",
        "scrollbar": "rgba(99, 115, 142, 0.72)",
        "scrollbar_hover": "rgba(124, 147, 185, 0.88)",
        "scrollbar_pressed": "rgba(146, 177, 225, 0.94)",
        "selection_bg": "#1d3556",
        "selection_fg": "#f7fbff",
        "surface_top": "#141b24",
        "surface_bottom": "#0d1218",
        "text_primary": "#d7e1ef",
        "text_strong": "#f7fbff",
        "text_muted": "#9aa9be",
        "text_soft": "#8191a6",
        "window_bg": "#090b10",
        "window_bg_secondary": "#06080c",
    },
    "typography": {
        "ui_family": '"Segoe UI Variable", "Inter", "Segoe UI", "Noto Sans", sans-serif',
        "mono_family": '"Cascadia Mono", "JetBrains Mono", "Consolas", monospace',
        "base_size": "13px",
        "title_size": "28px",
        "section_title_size": "15px",
    },
    "radii": {
        "badge": "12px",
        "button": "11px",
        "input": "14px",
        "panel": "18px",
        "surface": "16px",
    },
    "spacing": {
        "button_padding": "11px 16px",
        "chip_padding": "7px 12px",
        "status_padding": "8px 12px",
    },
    "semantic_colors": {
        "change": {
            "existing": {"background": "#1b212b", "foreground": "#b0bccd"},
            "live": {"background": "#132b20", "foreground": "#86efac"},
            "new": {"background": "#15263c", "foreground": "#8ec5ff"},
        },
        "run_states": {
            "blocked": {"background": "#3a2a16", "foreground": "#ffd089"},
            "cancelled": {"background": "#1b212b", "foreground": "#b0bccd"},
            "completed": {"background": "#142a20", "foreground": "#8ff0b0"},
            "failed": {"background": "#35171d", "foreground": "#ff9aaa"},
            "idle": {"background": "#1b212b", "foreground": "#b0bccd"},
            "paused": {"background": "#2a2237", "foreground": "#c8b4ff"},
            "running": {"background": "#13243a", "foreground": "#8ec5ff"},
        },
        "severity": {
            "critical": {"background": "#3a131c", "foreground": "#ff8fa3"},
            "high": {"background": "#40200f", "foreground": "#ffb37a"},
            "info": {"background": "#15263c", "foreground": "#8ec5ff"},
            "low": {"background": "#132b20", "foreground": "#86efac"},
            "medium": {"background": "#3b3012", "foreground": "#ffd87a"},
        },
        "workflow": {
            "confirmed": {"background": "#132b20", "foreground": "#86efac"},
            "duplicate": {"background": "#1b212b", "foreground": "#b0bccd"},
            "needs-validation": {"background": "#3b3012", "foreground": "#ffd87a"},
            "suppressed": {"background": "#281d40", "foreground": "#cdb4ff"},
        },
        "tool_status": {
            "blocked": {"background": "#3a2a16", "foreground": "#ffd089"},
            "cancelled": {"background": "#1b212b", "foreground": "#b0bccd"},
            "completed": {"background": "#142a20", "foreground": "#8ff0b0"},
            "failed": {"background": "#35171d", "foreground": "#ff9aaa"},
            "running": {"background": "#13243a", "foreground": "#8ec5ff"},
        },
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(dict(merged[key]), value)
        else:
            merged[key] = value
    return merged


def _normalized_extension_id(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return slug or "extension"


def default_extensions_root() -> Path:
    return Path.home() / ".attackcastle" / "extensions"


def default_extensions_state_path() -> Path:
    return Path.home() / ".attackcastle" / "gui_extensions_state.json"


def theme_semantic_maps(tokens: dict[str, Any] | None) -> dict[str, dict[str, tuple[str, str]]]:
    merged = _deep_merge(DEFAULT_THEME_TOKENS, tokens or {})
    semantic = merged.get("semantic_colors", {})
    normalized: dict[str, dict[str, tuple[str, str]]] = {}
    for group_name in ("run_states", "severity", "workflow", "change", "tool_status"):
        group = semantic.get(group_name, {})
        normalized[group_name] = {}
        if not isinstance(group, dict):
            continue
        for key, value in group.items():
            if not isinstance(value, dict):
                continue
            background = str(value.get("background", "")).strip()
            foreground = str(value.get("foreground", "")).strip()
            if background and foreground:
                normalized[group_name][str(key)] = (background, foreground)
    return normalized


def build_theme_stylesheet(tokens: dict[str, Any] | None = None, qss_append: str = "") -> str:
    merged = _deep_merge(DEFAULT_THEME_TOKENS, tokens or {})
    palette = merged["palette"]
    gradients = merged["gradients"]
    typography = merged["typography"]
    radii = merged["radii"]
    spacing = merged["spacing"]
    semantic = theme_semantic_maps(merged)
    run_states = semantic["run_states"]
    severity = semantic["severity"]
    workflow = semantic["workflow"]
    css = f"""
    QWidget {{
        background-color: {palette['window_bg']};
        color: {palette['text_primary']};
        font-size: {typography['base_size']};
        font-family: {typography['ui_family']};
    }}
    QWidget#appRoot {{
        background: qradialgradient(cx:0.15, cy:0.1, radius:1.0, fx:0.15, fy:0.1, stop:0 {gradients['app_shell']['start']}, stop:0.45 {gradients['app_shell']['mid']}, stop:1 {gradients['app_shell']['end']});
    }}
    QMainWindow {{ background-color: {palette['window_bg_secondary']}; }}
    QLabel {{ background: transparent; }}
    QLabel#logoBadge {{
        background: {palette['chip_bg']};
        border: 1px solid {palette['border_soft']};
        border-radius: {radii['surface']};
        padding: 10px;
    }}
    QFrame#headerPanel, QFrame#heroPanel, QFrame#statusPanel, QFrame#navRail {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {gradients['panel']['start']}, stop:0.55 {gradients['panel']['mid']}, stop:1 {gradients['panel']['end']});
        border: 1px solid {palette['border']};
        border-radius: {radii['panel']};
    }}
    QLabel#appTitle, QLabel#heroTitle {{ font-size: {typography['title_size']}; font-weight: 700; color: {palette['text_strong']}; background: transparent; letter-spacing: 0.2px; }}
    QLabel#appSubtitle {{ color: {palette['text_muted']}; font-size: 12px; font-weight: 600; background: transparent; }}
    QLabel#headerMeta {{ color: {palette['text_muted']}; background: transparent; }}
    QLabel#statusBadge {{
        color: {run_states['idle'][1]}; background: {run_states['idle'][0]}; border: 1px solid {palette['border']}; border-radius: {radii['badge']}; padding: {spacing['status_padding']}; font-weight: 700;
    }}
    QLabel#statusBadge[state="running"] {{ background: {run_states['running'][0]}; border-color: {palette['accent_border']}; color: {run_states['running'][1]}; }}
    QLabel#statusBadge[state="completed"] {{ background: {run_states['completed'][0]}; border-color: {palette['border']}; color: {run_states['completed'][1]}; }}
    QLabel#statusBadge[state="failed"], QLabel#statusBadge[state="blocked"] {{ background: {run_states['failed'][0]}; border-color: {palette['border']}; color: {run_states['failed'][1]}; }}
    QLabel#statusBadge[state="blocked"] {{ background: {run_states['blocked'][0]}; color: {run_states['blocked'][1]}; }}
    QLabel#statusBadge[state="paused"], QLabel#statusBadge[state="cancelled"], QLabel#statusBadge[state="idle"] {{ border-color: {palette['border']}; }}
    QLabel#statusBadge[state="paused"] {{ background: {run_states['paused'][0]}; color: {run_states['paused'][1]}; }}
    QLabel#statusBadge[state="cancelled"] {{ background: {run_states['cancelled'][0]}; color: {run_states['cancelled'][1]}; }}
    QLabel#statusBadge[state="idle"] {{ background: {run_states['idle'][0]}; color: {run_states['idle'][1]}; }}
    QLabel#sectionTitle {{ font-size: {typography['section_title_size']}; font-weight: 700; color: {palette['text_strong']}; padding-bottom: 2px; background: transparent; }}
    QLabel#outputSummary, QLabel#warningBanner, QLabel#statusBanner {{
        padding: 10px 12px; background: {palette['chip_bg']}; border: 1px solid {palette['border_soft']}; color: {palette['text_strong']}; border-radius: {radii['input']};
    }}
    QLabel#helperText, QLabel#sectionHelper {{ color: {palette['text_soft']}; background: transparent; }}
    QLabel#infoBanner {{ padding: 10px 12px; background: {palette['chip_bg']}; border: 1px solid {palette['border']}; color: {palette['text_primary']}; border-radius: {radii['input']}; }}
    QLabel#attentionBanner {{ padding: 10px 12px; border-radius: {radii['input']}; border: 1px solid {palette['border']}; background: {palette['chip_bg']}; color: {palette['text_primary']}; }}
    QLabel#attentionBanner[tone="alert"] {{ background: {severity['critical'][0]}; border-color: {palette['border']}; color: {severity['critical'][1]}; }}
    QLabel#attentionBanner[tone="warning"] {{ background: {severity['medium'][0]}; border-color: {palette['border']}; color: {severity['medium'][1]}; }}
    QLabel#attentionBanner[tone="ok"] {{ background: {workflow['confirmed'][0]}; border-color: {palette['border']}; color: {workflow['confirmed'][1]}; }}
    QFrame#summaryCard {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['surface_top']}, stop:1 {palette['surface_bottom']}); border: 1px solid {palette['border_soft']}; border-radius: {radii['surface']}; }}
    QFrame#toolbarPanel, QFrame#sidebarPanel, QFrame#subtlePanel, QFrame#collapsibleSection {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {gradients['surface']['start']}, stop:1 {gradients['surface']['end']}); border: 1px solid {palette['border_soft']}; border-radius: {radii['surface']}; }}
    QFrame#summaryCardAccent {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {gradients['summary_accent']['start']}, stop:0.5 {gradients['summary_accent']['mid']}, stop:1 {gradients['summary_accent']['end']}); border: 0; border-radius: 2px; }}
    QLabel#summaryCardTitle {{ color: {palette['text_soft']}; font-size: 11px; font-weight: 700; background: transparent; }}
    QLabel#summaryCardValue {{ color: {palette['text_strong']}; font-size: 26px; font-weight: 700; background: transparent; }}
    QLabel#summaryCardHint {{ color: {palette['text_muted']}; background: transparent; }}
    QGroupBox#panelGroup, QTabWidget::pane {{ border: 1px solid {palette['border_soft']}; background: {palette['surface_top']}; border-radius: {radii['surface']}; margin-top: 10px; padding: 8px; }}
    QGroupBox#panelGroup {{ font-weight: 700; color: {palette['text_strong']}; }}
    QGroupBox#panelGroup::title {{ subcontrol-origin: margin; left: 16px; top: 1px; padding: 0 6px; color: {palette['text_strong']}; background-color: {palette['surface_top']}; }}
    QTabBar::tab {{ padding: 9px 14px; margin: 4px 6px 4px 0; border-radius: {radii['button']}; background: {palette['surface_top']}; border: 1px solid {palette['border_soft']}; color: {palette['text_muted']}; font-weight: 600; min-height: 18px; }}
    QTabBar::tab:selected {{ background: {palette['chip_hover']}; border-color: {palette['accent_border']}; color: {palette['text_strong']}; }}
    QTabBar::tab:hover {{ border-color: {palette['border']}; color: {palette['text_strong']}; }}
    QPushButton {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['accent_primary']}, stop:1 {palette['accent_secondary']}); color: {palette['window_bg']}; border: 1px solid {palette['accent_border']}; border-radius: {radii['button']}; padding: {spacing['button_padding']}; font-weight: 700; min-height: 20px; }}
    QPushButton:hover {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['accent_soft']}, stop:1 {palette['accent_primary']}); }}
    QPushButton:disabled {{ background: {palette['panel_bottom']}; color: {palette['text_soft']}; border-color: {palette['border_soft']}; }}
    QPushButton[variant="secondary"] {{ background: {palette['surface_top']}; color: {palette['text_primary']}; border: 1px solid {palette['border']}; }}
    QPushButton[variant="secondary"]:hover {{ background: {palette['chip_hover']}; border-color: {palette['accent_border']}; }}
    QPushButton[variant="chip"] {{ background: {palette['chip_bg']}; color: {palette['text_muted']}; border: 1px solid {palette['border']}; padding: {spacing['chip_padding']}; }}
    QPushButton[variant="chip"]:hover {{ background: {palette['chip_hover']}; color: {palette['text_strong']}; }}
    QPushButton[variant="chip"]:checked {{ background: {palette['selection_bg']}; color: {palette['selection_fg']}; border-color: {palette['accent_soft']}; }}
    QToolButton {{ background: {palette['chip_bg']}; color: {palette['text_strong']}; border: 1px solid {palette['border']}; border-radius: {radii['button']}; padding: 8px 14px; font-weight: 600; min-height: 18px; }}
    QToolButton:hover {{ border-color: {palette['accent_border']}; }}
    QToolButton#sectionToggle {{ background: {palette['surface_top']}; border-color: {palette['border']}; text-align: left; }}
    QToolButton::menu-indicator {{ image: none; }}
    QMenu {{ background: {palette['surface_top']}; color: {palette['text_primary']}; border: 1px solid {palette['border']}; padding: 6px; }}
    QMenu::item {{ padding: 8px 14px; border-radius: 8px; }}
    QMenu::item:selected {{ background: {palette['chip_hover']}; }}
    QTableView, QListWidget, QTextEdit, QPlainTextEdit, QLineEdit, QComboBox, QSpinBox {{
        background: {palette['input_bg']}; border: 1px solid {palette['border_soft']}; border-radius: {radii['input']}; padding: 6px; alternate-background-color: {palette['chip_bg']}; selection-background-color: {palette['selection_bg']}; selection-color: {palette['selection_fg']}; gridline-color: {palette['border_soft']};
    }}
    QTableView#dataGrid, QTextEdit#consoleText, QLabel#monoLabel, QPlainTextEdit#extensionEditor {{
        font-family: {typography['mono_family']};
    }}
    QTableView {{ show-decoration-selected: 1; }}
    QTextEdit#richBrief {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {gradients['surface']['start']}, stop:1 {gradients['surface']['end']}); }}
    QTextEdit#consoleText, QPlainTextEdit#extensionEditor {{ background: {palette['input_bg']}; }}
    QLabel#previewSurface {{ background: {palette['input_bg']}; border: 1px solid {palette['border_soft']}; border-radius: {radii['input']}; color: {palette['text_soft']}; }}
    QListWidget#sidebarList::item, QListWidget#navList::item {{ margin: 3px 0; padding: 10px 12px; border-radius: 10px; border: 1px solid transparent; }}
    QListWidget#sidebarList::item:selected, QListWidget#navList::item:selected {{ background: {palette['selection_bg']}; border-color: {palette['accent_soft']}; color: {palette['text_strong']}; }}
    QHeaderView::section {{ background: {palette['panel_top']}; padding: 11px 12px; border: 0; border-bottom: 1px solid {palette['border_soft']}; font-weight: 700; color: {palette['text_muted']}; }}
    QFrame {{ background: {palette['surface_top']}; border: 1px solid {palette['border_soft']}; border-radius: {radii['input']}; }}
    QProgressBar {{ background: {palette['surface_bottom']}; border: 1px solid {palette['border_soft']}; border-radius: 8px; min-height: 10px; }}
    QProgressBar::chunk {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {palette['progress_start']}, stop:0.55 {palette['progress_mid']}, stop:1 {palette['progress_end']}); border-radius: 8px; }}
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px 1px 2px 1px; }}
    QScrollBar::handle:vertical {{ background: {palette['scrollbar']}; min-height: 28px; border-radius: 5px; }}
    QScrollBar::handle:vertical:hover {{ background: {palette['scrollbar_hover']}; }}
    QScrollBar::handle:vertical:pressed {{ background: {palette['scrollbar_pressed']}; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 1px 2px 1px 2px; }}
    QScrollBar::handle:horizontal {{ background: {palette['scrollbar']}; min-width: 28px; border-radius: 5px; }}
    QScrollBar::handle:horizontal:hover {{ background: {palette['scrollbar_hover']}; }}
    QScrollBar::handle:horizontal:pressed {{ background: {palette['scrollbar_pressed']}; }}
    QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{ background: none; border: none; }}
    QComboBox::drop-down {{ border: 0; width: 22px; }}
    QComboBox QAbstractItemView {{ background: {palette['surface_top']}; border: 1px solid {palette['border']}; selection-background-color: {palette['chip_hover']}; }}
    QCheckBox {{ spacing: 8px; background: transparent; }}
    QCheckBox::indicator {{ width: 18px; height: 18px; border-radius: 6px; border: 1px solid {palette['border']}; background: {palette['input_bg']}; }}
    QCheckBox::indicator:checked {{ background: {palette['accent_primary']}; border-color: {palette['accent_border']}; }}
    QScrollArea {{ background: transparent; border: 0; }}
    QSplitter::handle {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['panel_bottom']}, stop:1 {palette['chip_hover']});
        border: 1px solid {palette['border_soft']};
        border-radius: 5px;
        margin: 2px;
    }}
    QSplitter::handle:hover {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['chip_hover']}, stop:1 {palette['selection_bg']}); border-color: {palette['accent_border']}; }}
    QSplitter::handle:pressed {{ background: {palette['selection_bg']}; border-color: {palette['accent_soft']}; }}
    """
    appended = str(qss_append or "").strip()
    return css + ("\n" + appended if appended else "")


@dataclass(slots=True)
class ThemeExtensionConfig:
    tokens: dict[str, Any] = field(default_factory=lambda: json.loads(json.dumps(DEFAULT_THEME_TOKENS)))
    qss_append: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tokens": self.tokens,
            "qss_append": self.qss_append,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ThemeExtensionConfig":
        tokens = payload.get("tokens", {})
        return cls(
            tokens=dict(tokens) if isinstance(tokens, dict) else json.loads(json.dumps(DEFAULT_THEME_TOKENS)),
            qss_append=str(payload.get("qss_append", "")),
        )


@dataclass(slots=True)
class CommandHookExtensionConfig:
    hook: str = "pre_report"
    command: str = ""
    args: list[str] = field(default_factory=list)
    timeout_seconds: int = 300
    env: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hook": self.hook,
            "command": self.command,
            "args": list(self.args),
            "timeout_seconds": self.timeout_seconds,
            "env": dict(self.env),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CommandHookExtensionConfig":
        return cls(
            hook=str(payload.get("hook", "pre_report")) or "pre_report",
            command=str(payload.get("command", "")).strip(),
            args=[str(item) for item in payload.get("args", [])] if isinstance(payload.get("args"), list) else [],
            timeout_seconds=max(int(payload.get("timeout_seconds", 300) or 300), 1),
            env={str(key): str(value) for key, value in payload.get("env", {}).items()}
            if isinstance(payload.get("env"), dict)
            else {},
        )


@dataclass(slots=True)
class ExtensionReportPayload:
    title: str = ""
    cards: list[dict[str, Any]] = field(default_factory=list)
    tables: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "cards": list(self.cards),
            "tables": list(self.tables),
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ExtensionReportPayload":
        cards = payload.get("cards", [])
        tables = payload.get("tables", [])
        notes = payload.get("notes", [])
        return cls(
            title=str(payload.get("title", "")),
            cards=[dict(item) for item in cards if isinstance(item, dict)] if isinstance(cards, list) else [],
            tables=[dict(item) for item in tables if isinstance(item, dict)] if isinstance(tables, list) else [],
            notes=[str(item) for item in notes if str(item).strip()] if isinstance(notes, list) else [],
        )


@dataclass(slots=True)
class ExtensionManifest:
    schema_version: str
    extension_id: str
    name: str
    version: str
    description: str = ""
    capabilities: list[str] = field(default_factory=list)
    theme: ThemeExtensionConfig | None = None
    command_hook: CommandHookExtensionConfig | None = None
    report: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "id": self.extension_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": list(self.capabilities),
        }
        if self.theme is not None:
            payload["theme"] = self.theme.to_dict()
        if self.command_hook is not None:
            payload["command_hook"] = self.command_hook.to_dict()
        if self.report:
            payload["report"] = dict(self.report)
        return payload

    @property
    def is_theme(self) -> bool:
        return "theme" in self.capabilities and self.theme is not None

    @property
    def is_command_hook(self) -> bool:
        return "command_hook" in self.capabilities and self.command_hook is not None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ExtensionManifest":
        validate_extension_payload(payload)
        capabilities = [str(item) for item in payload.get("capabilities", [])]
        return cls(
            schema_version=str(payload["schema_version"]),
            extension_id=str(payload["id"]).strip(),
            name=str(payload["name"]).strip(),
            version=str(payload["version"]).strip(),
            description=str(payload.get("description", "")),
            capabilities=capabilities,
            theme=ThemeExtensionConfig.from_dict(payload["theme"]) if isinstance(payload.get("theme"), dict) else None,
            command_hook=CommandHookExtensionConfig.from_dict(payload["command_hook"])
            if isinstance(payload.get("command_hook"), dict)
            else None,
            report=dict(payload.get("report", {})) if isinstance(payload.get("report"), dict) else {},
        )


@dataclass(slots=True)
class ExtensionRecord:
    directory: Path
    manifest_path: Path
    manifest: ExtensionManifest | None
    raw_text: str
    load_error: str = ""
    enabled: bool = True
    active_theme: bool = False

    @property
    def extension_id(self) -> str:
        return self.manifest.extension_id if self.manifest is not None else self.directory.name

    @property
    def display_name(self) -> str:
        return self.manifest.name if self.manifest is not None else self.directory.name

    @property
    def capabilities(self) -> list[str]:
        return list(self.manifest.capabilities) if self.manifest is not None else []

    @property
    def is_valid(self) -> bool:
        return self.manifest is not None and not self.load_error


def validate_extension_payload(payload: dict[str, Any]) -> None:
    try:
        jsonschema.validate(instance=payload, schema=EXTENSION_MANIFEST_SCHEMA)
    except jsonschema.ValidationError as exc:  # noqa: PERF203
        path = ".".join(str(item) for item in exc.path) or "manifest"
        raise ExtensionValidationError(f"{path}: {exc.message}") from exc

    capabilities = {str(item) for item in payload.get("capabilities", [])}
    if "theme" in capabilities and not isinstance(payload.get("theme"), dict):
        raise ExtensionValidationError("theme capability requires a theme block.")
    if "command_hook" in capabilities and not isinstance(payload.get("command_hook"), dict):
        raise ExtensionValidationError("command_hook capability requires a command_hook block.")


def parse_extension_text(text: str) -> ExtensionManifest:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ExtensionValidationError(f"JSON parse error at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ExtensionValidationError("Extension manifest must be a JSON object.")
    return ExtensionManifest.from_dict(payload)


def extension_folder_name(manifest: ExtensionManifest) -> str:
    return _normalized_extension_id(manifest.extension_id)


def build_default_theme_manifest() -> ExtensionManifest:
    return ExtensionManifest(
        schema_version=EXTENSION_SCHEMA_VERSION,
        extension_id=DEFAULT_THEME_EXTENSION_ID,
        name=DEFAULT_THEME_EXTENSION_NAME,
        version="1.0.0",
        description=DEFAULT_THEME_EXTENSION_DESCRIPTION,
        capabilities=["theme"],
        theme=ThemeExtensionConfig(),
    )


def build_starter_theme_manifest(name: str = "New Theme Extension") -> ExtensionManifest:
    extension_id = _normalized_extension_id(name)
    return ExtensionManifest(
        schema_version=EXTENSION_SCHEMA_VERSION,
        extension_id=extension_id,
        name=name,
        version="1.0.0",
        description="Theme extension scaffold.",
        capabilities=["theme"],
        theme=ThemeExtensionConfig(),
    )


def build_starter_command_hook_manifest(name: str = "New Command Hook Extension") -> ExtensionManifest:
    extension_id = _normalized_extension_id(name)
    return ExtensionManifest(
        schema_version=EXTENSION_SCHEMA_VERSION,
        extension_id=extension_id,
        name=name,
        version="1.0.0",
        description="GUI-only command hook extension scaffold.",
        capabilities=["command_hook"],
        command_hook=CommandHookExtensionConfig(command="python", args=["-c", "print('hello from extension')"]),
    )
