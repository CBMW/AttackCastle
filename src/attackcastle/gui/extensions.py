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
            "start": "#090909",
            "mid": "#060606",
            "end": "#030303",
        },
        "panel": {
            "start": "#1b1b1b",
            "mid": "#141414",
            "end": "#0f0f0f",
        },
        "summary_accent": {
            "start": "#d6d6d6",
            "mid": "#a8a8a8",
            "end": "#7a7a7a",
        },
        "surface": {
            "start": "#161616",
            "end": "#0d0d0d",
        },
    },
    "palette": {
        "accent_border": "#d0d0d0",
        "accent_primary": "#e3e3e3",
        "accent_secondary": "#b8b8b8",
        "accent_soft": "#f1f1f1",
        "banner_bg": "rgba(18, 18, 18, 0.86)",
        "border": "#5f5f5f",
        "border_soft": "#343434",
        "chip_bg": "#171717",
        "chip_hover": "#242424",
        "control_group_bg": "rgba(15, 15, 15, 0.66)",
        "danger_border": "#9d4450",
        "danger_hover": "#481921",
        "danger_hover_border": "#bd5a69",
        "danger_text": "#ffd7dc",
        "hero_end": "#070707",
        "hero_glow": "#171717",
        "hero_mid": "#101010",
        "info_bg": "rgba(18, 18, 18, 0.9)",
        "input_bg": "#101010",
        "mono_bg": "rgba(12, 12, 12, 0.76)",
        "panel_top": "#1b1b1b",
        "panel_mid": "#141414",
        "panel_bottom": "#0f0f0f",
        "progress_start": "#4ade80",
        "progress_mid": "#a8a8a8",
        "progress_end": "#f1f1f1",
        "profile_tool_summary_bg": "rgba(26, 26, 26, 0.74)",
        "scanner_start_hover_bg": "rgba(74, 222, 128, 0.14)",
        "scanner_start_hover_border": "rgba(74, 222, 128, 0.45)",
        "scanner_start_hover_text": "#8dffb2",
        "scrollbar": "rgba(112, 112, 112, 0.72)",
        "scrollbar_hover": "rgba(145, 145, 145, 0.88)",
        "scrollbar_pressed": "rgba(178, 178, 178, 0.94)",
        "selection_bg": "#303030",
        "selection_fg": "#ffffff",
        "splitter_handle": "rgba(96, 96, 96, 0.16)",
        "splitter_handle_hover": "rgba(145, 145, 145, 0.26)",
        "splitter_handle_pressed": "rgba(190, 190, 190, 0.34)",
        "surface_overlay": "rgba(18, 18, 18, 0.9)",
        "surface_overlay_strong": "rgba(18, 18, 18, 0.94)",
        "surface_top": "#161616",
        "surface_bottom": "#0d0d0d",
        "text_primary": "#d8d8d8",
        "text_strong": "#f7f7f7",
        "text_muted": "#a6a6a6",
        "text_soft": "#828282",
        "window_bg": "#060606",
        "window_bg_secondary": "#030303",
    },
    "typography": {
        "ui_family": '"Segoe UI Variable", "Inter", "Segoe UI", "Noto Sans", sans-serif',
        "mono_family": '"Cascadia Mono", "JetBrains Mono", "Consolas", monospace',
        "base_size": "13px",
        "title_size": "28px",
        "section_title_size": "15px",
    },
    "radii": {
        "badge": "4px",
        "button": "3px",
        "input": "3px",
        "panel": "3px",
        "section": "3px",
        "surface": "3px",
    },
    "spacing": {
        "button_padding": "5px 9px",
        "chip_padding": "3px 8px",
        "status_padding": "4px 8px",
    },
    "semantic_colors": {
        "change": {
            "existing": {"background": "#202020", "foreground": "#bdbdbd"},
            "live": {"background": "#132b20", "foreground": "#86efac"},
            "new": {"background": "#232323", "foreground": "#f1f1f1"},
        },
        "run_states": {
            "blocked": {"background": "#3a2a16", "foreground": "#ffd089"},
            "cancelled": {"background": "#202020", "foreground": "#bdbdbd"},
            "completed": {"background": "#142a20", "foreground": "#8ff0b0"},
            "failed": {"background": "#35171d", "foreground": "#ff9aaa"},
            "idle": {"background": "#202020", "foreground": "#bdbdbd"},
            "paused": {"background": "#2a2a2a", "foreground": "#d6d6d6"},
            "running": {"background": "#132b20", "foreground": "#86efac"},
        },
        "severity": {
            "critical": {"background": "#3a131c", "foreground": "#ff8fa3"},
            "high": {"background": "#40200f", "foreground": "#ffb37a"},
            "info": {"background": "#202020", "foreground": "#d6d6d6"},
            "low": {"background": "#132b20", "foreground": "#86efac"},
            "medium": {"background": "#3b3012", "foreground": "#ffd87a"},
        },
        "workflow": {
            "confirmed": {"background": "#132b20", "foreground": "#86efac"},
            "duplicate": {"background": "#202020", "foreground": "#bdbdbd"},
            "needs-validation": {"background": "#3b3012", "foreground": "#ffd87a"},
            "suppressed": {"background": "#252525", "foreground": "#c9c9c9"},
        },
        "tool_status": {
            "blocked": {"background": "#3a2a16", "foreground": "#ffd089"},
            "cancelled": {"background": "#202020", "foreground": "#bdbdbd"},
            "completed": {"background": "#142a20", "foreground": "#8ff0b0"},
            "failed": {"background": "#35171d", "foreground": "#ff9aaa"},
            "running": {"background": "#132b20", "foreground": "#86efac"},
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
        background: transparent;
        color: {palette['text_primary']};
        font-size: {typography['base_size']};
        font-family: {typography['ui_family']};
    }}
    QWidget#appRoot {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {gradients['app_shell']['start']}, stop:0.62 {gradients['app_shell']['mid']}, stop:1 {gradients['app_shell']['end']});
    }}
    QMainWindow, QDialog {{
        background-color: {palette['window_bg_secondary']};
    }}
    QLabel {{ background: transparent; }}
    QLabel#logoBadge {{
        background: {palette['chip_bg']};
        border: 1px solid {palette['border_soft']};
        border-radius: {radii['surface']};
        padding: 7px;
    }}
    QFrame, QWidget[surface], QFrame[surface] {{
        background: transparent;
        border: 0;
        border-radius: 0;
    }}
    QFrame#headerPanel,
    QFrame#heroPanel,
    QFrame#statusPanel,
    QFrame#sidebarPanel,
    QFrame#inspectorPanel,
    QFrame[surface="primary"] {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {gradients['panel']['start']}, stop:0.55 {gradients['panel']['mid']}, stop:1 {gradients['panel']['end']});
        border: 1px solid {palette['border']};
        border-radius: {radii['panel']};
    }}
    QFrame#toolbarPanel,
    QFrame#subtlePanel,
    QFrame#overviewChecklistPanel,
    QFrame[surface="secondary"] {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['surface_top']}, stop:1 {palette['input_bg']});
        border: 1px solid {palette['border_soft']};
        border-radius: {radii['surface']};
    }}
    QWidget#sectionBlock,
    QFrame#collapsibleSection,
    QWidget[surface="flat"],
    QFrame[surface="flat"] {{
        background: transparent;
        border: 0;
        border-radius: 0;
    }}
    QWidget#settingsContent {{
        background: transparent;
    }}
    QScrollArea#settingsScroll {{
        background: transparent;
        border: 0;
    }}
    QFrame#settingsCard,
    QFrame#settingsPrimaryCard {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {gradients['panel']['start']}, stop:0.58 {gradients['panel']['mid']}, stop:1 {gradients['panel']['end']});
        border: 1px solid {palette['border_soft']};
        border-radius: 9px;
    }}
    QFrame#settingsPrimaryCard {{
        border-color: {palette['border']};
    }}
    QFrame#settingsDangerCard {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['chip_bg']}, stop:1 {palette['panel_bottom']});
        border: 1px solid {palette['danger_border']};
        border-radius: 9px;
    }}
    QFrame#settingsControlGroup {{
        background: {palette['control_group_bg']};
        border: 1px solid {palette['border_soft']};
        border-radius: 8px;
    }}
    QFrame#settingsDivider {{
        background: transparent;
        border: 0;
        border-top: 1px solid {palette['border_soft']};
        min-height: 1px;
        max-height: 1px;
    }}
    QFrame#profileSummaryCard,
    QFrame#profileCard,
    QFrame#profileActionCard {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {gradients['panel']['start']}, stop:0.58 {gradients['panel']['mid']}, stop:1 {gradients['panel']['end']});
        border: 1px solid {palette['border_soft']};
        border-radius: 10px;
    }}
    QFrame#profileSummaryCard {{
        border-color: {palette['border']};
    }}
    QFrame#profileActionCard {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['surface_top']}, stop:1 {palette['input_bg']});
        border-color: {palette['border']};
    }}
    QFrame#profileSubCard,
    QFrame#toolFamilyCard,
    QFrame#toolCoverageCategory {{
        background: {palette['control_group_bg']};
        border: 1px solid {palette['border_soft']};
        border-radius: 8px;
    }}
    QFrame#toolCoverageRow {{
        background: rgba(255, 255, 255, 0.018);
        border: 1px solid {palette['border_soft']};
        border-radius: 7px;
    }}
    QFrame#toolCoverageRow[available="false"] {{
        background: rgba(255, 255, 255, 0.012);
        border-color: {palette['border_soft']};
    }}
    QWidget#profilePresetPanel,
    QWidget#profileBrowseRow,
    QWidget#toolCoverageBody,
    QWidget#expertToolPanel,
    QFrame#profileLibraryActions {{
        background: transparent;
    }}
    QLabel#profileSummaryName {{
        color: {palette['text_strong']};
        font-size: 20px;
        font-weight: 700;
        background: transparent;
    }}
    QLabel#profileSummaryDescription {{
        color: {palette['text_primary']};
        background: transparent;
    }}
    QLabel#profileChip {{
        padding: 4px 8px;
        background: {palette['chip_bg']};
        border: 1px solid {palette['border_soft']};
        border-radius: 6px;
        color: {palette['text_muted']};
        font-size: 11px;
        font-weight: 700;
    }}
    QLabel#profileGroupTitle {{
        color: {palette['text_strong']};
        font-size: 13px;
        font-weight: 700;
        background: transparent;
    }}
    QLabel#profileToolSummary {{
        padding: 4px 8px;
        background: {palette['profile_tool_summary_bg']};
        border: 1px solid {palette['border_soft']};
        border-radius: 6px;
        color: {palette['accent_soft']};
        font-weight: 700;
    }}
    QLabel#profileToolList {{
        color: {palette['text_soft']};
        background: transparent;
    }}
    QLabel#toolCoverageName {{
        color: {palette['text_strong']};
        font-weight: 700;
        background: transparent;
    }}
    QLabel#toolCoverageName[available="false"] {{
        color: {severity['critical'][1]};
    }}
    QDialog#launchScanDialog QScrollArea#launchDialogScroll,
    QDialog#launchScanDialog QWidget#launchDialogContent {{
        background: transparent;
        border: 0;
    }}
    QDialog#launchScanDialog QGroupBox#launchPanelGroup {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['surface_top']}, stop:1 {palette['input_bg']});
        border: 1px solid {palette['border_soft']};
        border-radius: 8px;
        margin-top: 8px;
        padding-top: 10px;
        color: {palette['text_strong']};
        font-weight: 700;
    }}
    QDialog#launchScanDialog QGroupBox#launchPanelGroup::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 10px;
        top: 0;
        padding: 0 4px;
        background: transparent;
        color: {palette['text_strong']};
        letter-spacing: 0;
    }}
    QDialog#launchScanDialog QFrame#launchAdvancedPanel {{
        background: transparent;
        border: 0;
    }}
    QDialog#launchScanDialog QFrame#profileCard {{
        background: {palette['control_group_bg']};
        border: 1px solid {palette['border_soft']};
        border-radius: 8px;
    }}
    QDialog#launchScanDialog QFrame#profileSubCard,
    QDialog#launchScanDialog QFrame#toolCoverageCategory {{
        background: rgba(255, 255, 255, 0.014);
        border: 1px solid {palette['border_soft']};
        border-radius: 7px;
    }}
    QDialog#launchScanDialog QFrame#toolCoverageRow {{
        background: rgba(255, 255, 255, 0.012);
        border: 1px solid rgba(95, 95, 95, 0.46);
        border-radius: 6px;
    }}
    QDialog#launchScanDialog QPushButton#launchAdvancedToggle {{
        min-height: 24px;
        padding: 4px 10px;
    }}
    QDialog#launchScanDialog QLabel#infoBanner,
    QDialog#launchScanDialog QLabel#attentionBanner {{
        padding: 6px 8px;
        background: {palette['info_bg']};
        border: 1px solid {palette['border_soft']};
        border-radius: 6px;
    }}
    QDialog#launchScanDialog QLabel#attentionBanner[tone="alert"] {{
        background: {severity['critical'][0]};
        border-color: {palette['border']};
        color: {severity['critical'][1]};
    }}
    QDialog#launchScanDialog QLabel#attentionBanner[tone="warning"] {{
        background: {severity['medium'][0]};
        border-color: {palette['border']};
        color: {severity['medium'][1]};
    }}
    QDialog#launchScanDialog QLabel#attentionBanner[tone="ok"] {{
        background: {workflow['confirmed'][0]};
        border-color: {palette['border']};
        color: {workflow['confirmed'][1]};
    }}
    QDialog#launchScanDialog QListWidget#sidebarList {{
        background: {palette['input_bg']};
        border: 1px solid {palette['border_soft']};
        border-radius: 6px;
        padding: 2px;
    }}
    QLabel#appTitle, QLabel#heroTitle {{ font-size: {typography['title_size']}; font-weight: 700; color: {palette['text_strong']}; background: transparent; letter-spacing: 0; }}
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
        padding: 5px 0 5px 8px;
        background: {palette['banner_bg']};
        border: 0;
        border-left: 3px solid {palette['border']};
        color: {palette['text_strong']};
        border-radius: 0;
    }}
    QLabel#helperText, QLabel#sectionHelper {{ color: {palette['text_soft']}; background: transparent; }}
    QLabel#settingsFieldLabel {{
        color: {palette['text_primary']};
        font-weight: 700;
        background: transparent;
    }}
    QLabel#monoLabel[variant="path"] {{
        background: {palette['mono_bg']};
        border: 1px solid {palette['border_soft']};
        border-radius: 6px;
        color: {palette['text_soft']};
        padding: 7px 8px;
    }}
    QLabel#infoBanner {{
        padding: 5px 8px;
        background: {palette['info_bg']};
        border: 1px solid {palette['border_soft']};
        color: {palette['text_primary']};
        border-radius: {radii['section']};
    }}
    QLabel#scannerRunName {{ color: {palette['text_strong']}; font-size: 18px; font-weight: 700; background: transparent; }}
    QLabel#scannerRunContext {{ color: {palette['text_muted']}; background: transparent; }}
    QLabel#scannerRunSummaryText {{ color: {palette['text_primary']}; background: transparent; }}
    QLabel#scannerActionGroupLabel {{ color: {palette['text_muted']}; font-size: 11px; font-weight: 700; letter-spacing: 0; background: transparent; }}
    QLabel#attentionBanner {{
        padding: 6px 8px;
        border-radius: {radii['section']};
        border: 1px solid {palette['border_soft']};
        background: {palette['info_bg']};
        color: {palette['text_primary']};
    }}
    QLabel#attentionBanner[tone="alert"] {{ background: {severity['critical'][0]}; border-color: {palette['border']}; color: {severity['critical'][1]}; }}
    QLabel#attentionBanner[tone="warning"] {{ background: {severity['medium'][0]}; border-color: {palette['border']}; color: {severity['medium'][1]}; }}
    QLabel#attentionBanner[tone="ok"] {{ background: {workflow['confirmed'][0]}; border-color: {palette['border']}; color: {workflow['confirmed'][1]}; }}
    QFrame#summaryCard {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['surface_top']}, stop:1 {palette['surface_bottom']}); border: 1px solid {palette['border_soft']}; border-radius: {radii['surface']}; }}
    QFrame#summaryCardAccent {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {gradients['summary_accent']['start']}, stop:0.5 {gradients['summary_accent']['mid']}, stop:1 {gradients['summary_accent']['end']}); border: 0; border-radius: 2px; }}
    QLabel#summaryCardTitle {{ color: {palette['text_soft']}; font-size: 11px; font-weight: 700; background: transparent; }}
    QLabel#summaryCardValue {{ color: {palette['text_strong']}; font-size: 26px; font-weight: 700; background: transparent; }}
    QLabel#summaryCardHint {{ color: {palette['text_muted']}; background: transparent; }}
    QGroupBox#panelGroup, QGroupBox#panelGroupUntitled {{
        background: transparent;
        border: 0;
        border-radius: 0;
        padding: 0;
    }}
    QGroupBox#panelGroup {{
        margin-top: 6px;
        border-top: 1px solid {palette['border_soft']};
        padding-top: 5px;
        font-weight: 700;
        color: {palette['text_strong']};
    }}
    QGroupBox#panelGroupUntitled {{ margin-top: 0; padding-top: 0; }}
    QGroupBox#panelGroup::title {{
        subcontrol-origin: margin;
        left: 0;
        top: 0;
        padding: 0 0 4px 0;
        color: {palette['text_muted']};
        background: transparent;
        letter-spacing: 0;
    }}
    QTabWidget::pane {{
        border: 0;
        background: transparent;
        padding: 0;
        margin-top: 3px;
    }}
    QTabBar::tab {{
        background: transparent;
        border: 0;
        border-bottom: 2px solid transparent;
        border-radius: 0;
        color: {palette['text_muted']};
        padding: 6px 10px 5px 10px;
        margin: 0 7px 0 0;
        min-height: 18px;
        font-weight: 700;
    }}
    QTabBar::tab:selected {{ background: transparent; border-bottom-color: {palette['accent_border']}; color: {palette['text_strong']}; }}
    QTabBar::tab:hover {{ background: transparent; border-bottom-color: {palette['border']}; color: {palette['text_strong']}; }}
    QTabWidget#masterTabs::pane,
    QTabWidget#workflowTabs::pane {{
        border: 0;
        background: transparent;
        margin-top: 6px;
        padding: 0;
    }}
    QTabBar#masterTabBar,
    QTabBar#workflowTabBar {{
        qproperty-drawBase: 0;
    }}
    QTabBar#masterTabBar::tab,
    QTabBar#workflowTabBar::tab {{
        background: transparent;
        border: 0;
        border-bottom: 2px solid transparent;
        border-radius: 0;
        color: {palette['text_muted']};
        padding: 7px 12px 6px 12px;
        margin: 0 8px 0 0;
        min-height: 20px;
        font-weight: 700;
    }}
    QTabBar#masterTabBar::tab:selected,
    QTabBar#workflowTabBar::tab:selected {{
        background: transparent;
        border-bottom-color: {palette['accent_border']};
        color: {palette['text_strong']};
    }}
    QTabBar#masterTabBar::tab:hover,
    QTabBar#workflowTabBar::tab:hover {{
        background: transparent;
        border-bottom-color: {palette['border']};
        color: {palette['text_strong']};
    }}
    QTabWidget#groupTabs::pane,
    QTabWidget#inspectorTabs::pane {{
        border: 0;
        background: transparent;
        margin-top: 4px;
        padding: 0;
    }}
    QTabBar#groupTabBar::tab,
    QTabBar#inspectorTabBar::tab {{
        padding: 5px 9px 4px 9px;
        margin: 0 6px 0 0;
        min-height: 17px;
    }}
    QTabBar#inspectorTabBar::tab {{
        color: {palette['text_soft']};
    }}
    QPushButton {{ background: {palette['accent_primary']}; color: {palette['window_bg']}; border: 1px solid {palette['accent_border']}; border-radius: {radii['button']}; padding: {spacing['button_padding']}; font-weight: 700; min-height: 18px; }}
    QPushButton:hover {{ background: {palette['accent_soft']}; }}
    QPushButton:disabled {{ background: {palette['panel_bottom']}; color: {palette['text_soft']}; border-color: {palette['border_soft']}; }}
    QPushButton#scannerStartButton {{
        min-width: 24px;
        max-width: 28px;
        min-height: 24px;
        max-height: 28px;
        padding: 0;
        border: 0;
        background: transparent;
        color: {palette['progress_start']};
        font-size: 16px;
        font-weight: 900;
    }}
    QPushButton#scannerStartButton:hover {{
        background: {palette['scanner_start_hover_bg']};
        border: 1px solid {palette['scanner_start_hover_border']};
        color: {palette['scanner_start_hover_text']};
    }}
    QPushButton#scannerStartButton:disabled {{
        background: transparent;
        border: 0;
        color: {palette['text_soft']};
    }}
    QPushButton#scannerActionButton, QPushButton#scannerDangerButton {{ padding: 4px 8px; }}
    QPushButton[variant="secondary"] {{ background: rgba(16, 22, 31, 0.88); color: {palette['text_primary']}; border: 1px solid {palette['border_soft']}; }}
    QPushButton[variant="secondary"]:hover {{ background: {palette['chip_hover']}; border-color: {palette['border']}; }}
    QPushButton[variant="danger"] {{ background: {severity['critical'][0]}; color: {severity['critical'][1]}; border: 1px solid {palette['danger_border']}; }}
    QPushButton[variant="danger"]:hover {{ background: {palette['danger_hover']}; border-color: {palette['danger_hover_border']}; color: {palette['text_strong']}; }}
    QPushButton[variant="chip"] {{ background: {palette['chip_bg']}; color: {palette['text_muted']}; border: 1px solid {palette['border']}; padding: {spacing['chip_padding']}; }}
    QPushButton[variant="chip"]:hover {{ background: {palette['chip_hover']}; color: {palette['text_strong']}; }}
    QPushButton[variant="chip"]:checked {{ background: {palette['selection_bg']}; color: {palette['selection_fg']}; border-color: {palette['accent_soft']}; }}
    QFrame#settingsCard QPushButton,
    QFrame#settingsPrimaryCard QPushButton,
    QFrame#settingsDangerCard QPushButton {{
        border-radius: 6px;
        min-height: 24px;
    }}
    QPushButton#browseButton {{
        min-width: 74px;
        max-width: 92px;
        border-radius: 6px;
    }}
    QPushButton[libraryAction="true"] {{
        min-width: 36px;
        max-width: 36px;
        min-height: 32px;
        max-height: 32px;
        padding: 0;
        border-radius: 7px;
    }}
    QPushButton#profilePrimaryAction {{
        min-height: 32px;
    }}
    QPushButton#profileDangerAction {{
        min-height: 32px;
        color: {palette['danger_text']};
        font-size: 16px;
        font-weight: 900;
    }}
    QPushButton#profileDangerAction:hover {{ color: {palette['text_strong']}; }}
    QToolButton {{ background: {palette['surface_overlay']}; color: {palette['text_strong']}; border: 1px solid {palette['border_soft']}; border-radius: {radii['button']}; padding: 4px 8px; font-weight: 600; min-height: 16px; }}
    QToolButton:hover {{ border-color: {palette['border']}; }}
    QToolButton#sectionToggle {{
        background: transparent;
        border: 0;
        border-top: 1px solid {palette['border_soft']};
        border-radius: 0;
        padding: 6px 0 0 0;
        text-align: left;
        color: {palette['text_strong']};
    }}
    QToolButton::menu-indicator {{ image: none; }}
    QMenu {{ background: {palette['surface_top']}; color: {palette['text_primary']}; border: 1px solid {palette['border']}; padding: 4px; }}
    QMenu::item {{ padding: 4px 10px; border-radius: {radii['section']}; }}
    QMenu::item:selected {{ background: {palette['chip_hover']}; }}
    QTableView, QListWidget, QTextEdit, QPlainTextEdit, QLineEdit, QComboBox, QSpinBox {{
        background: {palette['input_bg']}; border: 1px solid {palette['border_soft']}; border-radius: {radii['input']}; padding: 3px; alternate-background-color: {palette['chip_bg']}; selection-background-color: {palette['selection_bg']}; selection-color: {palette['selection_fg']}; gridline-color: {palette['border_soft']};
    }}
    QTableView#dataGrid, QTextEdit#consoleText, QLabel#monoLabel, QPlainTextEdit#extensionEditor {{
        font-family: {typography['mono_family']};
    }}
    QTableView {{ show-decoration-selected: 1; }}
    QTextEdit#richBrief {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {gradients['surface']['start']}, stop:1 {gradients['surface']['end']});
        border-radius: {radii['surface']};
    }}
    QTextEdit#consoleText, QPlainTextEdit#extensionEditor {{ background: {palette['input_bg']}; }}
    QLabel#previewSurface {{ background: {palette['input_bg']}; border: 1px solid {palette['border_soft']}; border-radius: {radii['input']}; color: {palette['text_soft']}; }}
    QListWidget#sidebarList {{
        background: transparent;
        border: 0;
        padding: 0;
    }}
    QListWidget#sidebarList::item {{ margin: 1px 0; padding: 5px 8px; border-radius: 7px; border: 1px solid transparent; }}
    QListWidget#sidebarList::item:hover {{ background: {palette['chip_hover']}; border-color: {palette['border_soft']}; color: {palette['text_strong']}; }}
    QListWidget#sidebarList::item:selected {{ background: {palette['selection_bg']}; border-color: {palette['accent_soft']}; color: {palette['text_strong']}; }}
    QFrame#profileCard QLineEdit,
    QFrame#profileCard QComboBox,
    QFrame#profileCard QSpinBox {{
        min-height: 24px;
        padding: 4px 6px;
    }}
    QFrame#profileCard QCheckBox {{
        spacing: 9px;
        min-height: 24px;
    }}
    QHeaderView::section {{ background: {palette['panel_top']}; padding: 5px 8px; border: 0; border-bottom: 1px solid {palette['border_soft']}; font-weight: 700; color: {palette['text_muted']}; }}
    QProgressBar {{ background: {palette['surface_bottom']}; border: 1px solid {palette['border_soft']}; border-radius: {radii['section']}; min-height: 10px; }}
    QProgressBar::chunk {{ background: {palette['progress_mid']}; border-radius: {radii['section']}; }}
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px 1px 2px 1px; }}
    QScrollBar::handle:vertical {{ background: {palette['scrollbar']}; min-height: 28px; border-radius: {radii['section']}; }}
    QScrollBar::handle:vertical:hover {{ background: {palette['scrollbar_hover']}; }}
    QScrollBar::handle:vertical:pressed {{ background: {palette['scrollbar_pressed']}; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 1px 2px 1px 2px; }}
    QScrollBar::handle:horizontal {{ background: {palette['scrollbar']}; min-width: 28px; border-radius: {radii['section']}; }}
    QScrollBar::handle:horizontal:hover {{ background: {palette['scrollbar_hover']}; }}
    QScrollBar::handle:horizontal:pressed {{ background: {palette['scrollbar_pressed']}; }}
    QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{ background: none; border: none; }}
    QComboBox::drop-down {{ border: 0; width: 18px; }}
    QComboBox QAbstractItemView {{ background: {palette['surface_top']}; border: 1px solid {palette['border']}; selection-background-color: {palette['chip_hover']}; }}
    QCheckBox {{ spacing: 8px; background: transparent; }}
    QCheckBox::indicator {{ width: 18px; height: 18px; border-radius: {radii['badge']}; border: 1px solid {palette['border']}; background: {palette['input_bg']}; }}
    QCheckBox::indicator:checked {{ background: {palette['accent_primary']}; border-color: {palette['accent_border']}; }}
    QCheckBox::indicator:disabled {{ background: rgba(157, 68, 80, 0.12); border-color: {palette['danger_border']}; }}
    QSlider::groove:horizontal {{
        height: 6px;
        background: {palette['input_bg']};
        border: 1px solid {palette['border_soft']};
        border-radius: 4px;
    }}
    QSlider::sub-page:horizontal {{
        background: {palette['accent_primary']};
        border: 1px solid {palette['accent_border']};
        border-radius: 4px;
    }}
    QSlider::add-page:horizontal {{
        background: {palette['chip_bg']};
        border: 1px solid {palette['border_soft']};
        border-radius: 4px;
    }}
    QSlider::handle:horizontal {{
        width: 18px;
        height: 18px;
        margin: -7px 0;
        background: {palette['text_strong']};
        border: 2px solid {palette['accent_border']};
        border-radius: 9px;
    }}
    QSlider::handle:horizontal:hover {{
        background: {palette['accent_soft']};
    }}
    QWidget#overviewChecklistHeader, QWidget#overviewChecklistListContainer {{ background: transparent; }}
    QLabel#overviewChecklistTitle {{ color: {palette['text_strong']}; font-size: 16px; font-weight: 700; letter-spacing: 0; background: transparent; }}
    QLabel#overviewChecklistSummary {{ color: {palette['text_soft']}; background: transparent; }}
    QLabel#overviewChecklistCountBadge {{
        padding: 5px 8px;
        background: {palette['chip_bg']};
        border: 1px solid {palette['border']};
        border-radius: {radii['badge']};
        color: {palette['text_muted']};
        font-size: 11px;
        font-weight: 700;
    }}
    QLabel#overviewChecklistCountBadge[tone="ready"] {{ background: {run_states['idle'][0]}; color: {run_states['idle'][1]}; border-color: {palette['border']}; }}
    QLabel#overviewChecklistCountBadge[tone="active"] {{ background: {run_states['running'][0]}; color: {run_states['running'][1]}; border-color: {palette['accent_border']}; }}
    QLabel#overviewChecklistCountBadge[tone="complete"] {{ background: {workflow['confirmed'][0]}; color: {workflow['confirmed'][1]}; border-color: {palette['border']}; }}
    QFrame#overviewChecklistComposer {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['input_bg']}, stop:1 {palette['panel_bottom']});
        border: 1px solid {palette['border_soft']};
        border-radius: {radii['input']};
    }}
    QFrame#overviewChecklistComposer:hover {{ border-color: {palette['border']}; }}
    QFrame#overviewChecklistComposer[focusWithin="true"] {{ border-color: {palette['accent_border']}; background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['chip_bg']}, stop:1 {palette['input_bg']}); }}
    QLineEdit#overviewChecklistInput {{
        background: transparent;
        border: 0;
        padding: 7px 4px;
        color: {palette['text_primary']};
        selection-background-color: {palette['selection_bg']};
        selection-color: {palette['selection_fg']};
    }}
    QLineEdit#overviewChecklistInput:focus {{ border: 0; }}
    QPushButton#overviewChecklistAddButton {{
        min-height: 32px;
        padding: 0 14px;
        border-radius: {radii['button']};
        background: {palette['accent_primary']};
        color: {palette['window_bg']};
        border: 1px solid {palette['accent_border']};
    }}
    QPushButton#overviewChecklistAddButton:hover {{ background: {palette['accent_soft']}; }}
    QPushButton#overviewChecklistAddButton:disabled {{ background: {palette['panel_bottom']}; color: {palette['text_soft']}; border-color: {palette['border_soft']}; }}
    QFrame#overviewChecklistListSurface {{ background: transparent; border: 0; border-radius: 0; }}
    QWidget#scannerLaunchCard, QWidget#scannerRunCard, QWidget#scannerActionSection {{
        background: transparent;
    }}
    QFrame#scannerMetricTile {{
        background: {palette['surface_overlay']};
        border: 1px solid {palette['border_soft']};
        border-radius: {radii['input']};
    }}
    QFrame#scannerMetricTile:hover {{
        border-color: {palette['border']};
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['chip_hover']}, stop:1 {palette['surface_bottom']});
    }}
    QLabel#scannerMetricLabel {{ color: {palette['text_soft']}; font-size: 11px; font-weight: 700; background: transparent; }}
    QLabel#scannerMetricValue {{ color: {palette['text_strong']}; font-weight: 700; background: transparent; }}
    QFrame#overviewChecklistItemCard {{
        background: {palette['surface_overlay_strong']};
        border: 1px solid {palette['border_soft']};
        border-radius: {radii['input']};
    }}
    QFrame#overviewChecklistItemCard:hover {{
        border-color: {palette['accent_border']};
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['chip_hover']}, stop:1 {palette['surface_bottom']});
    }}
    QFrame#overviewChecklistItemCard[completed="true"] {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['chip_bg']}, stop:1 {palette['surface_bottom']});
        border-color: {palette['border']};
    }}
    QCheckBox#overviewChecklistToggle {{ spacing: 0; }}
    QCheckBox#overviewChecklistToggle::indicator {{
        width: 20px;
        height: 20px;
        border-radius: {radii['badge']};
        border: 1px solid {palette['border']};
        background: {palette['window_bg']};
    }}
    QCheckBox#overviewChecklistToggle::indicator:hover {{ border-color: {palette['accent_border']}; background: {palette['chip_bg']}; }}
    QCheckBox#overviewChecklistToggle::indicator:checked {{
        background: {palette['accent_primary']};
        border-color: {palette['accent_border']};
    }}
    QLabel#overviewChecklistItemLabel {{ color: {palette['text_primary']}; background: transparent; }}
    QLabel#overviewChecklistItemLabel[completed="true"] {{ color: {palette['text_soft']}; }}
    QPushButton#overviewChecklistDelete {{
        background: transparent;
        border: 1px solid transparent;
        border-radius: {radii['button']};
        color: {palette['text_soft']};
        font-weight: 700;
        padding: 0;
    }}
    QPushButton#overviewChecklistDelete:hover {{
        background: {severity['critical'][0]};
        border-color: {palette['danger_border']};
        color: {severity['critical'][1]};
    }}
    QFrame#overviewChecklistEmptyState {{ background: transparent; border: 0; }}
        QLabel#overviewChecklistEmptyIcon {{
            color: {palette['accent_soft']};
            font-size: 18px;
            font-weight: 700;
            padding: 0px;
        }}
    QLabel#overviewChecklistEmptyTitle {{ color: {palette['text_strong']}; font-weight: 700; background: transparent; }}
    QLabel#overviewChecklistEmptySummary {{ color: {palette['text_soft']}; background: transparent; }}
    QScrollArea {{ background: transparent; border: 0; }}
    QScrollArea#overviewChecklistScroll {{ background: transparent; border: 0; }}
    QSplitter::handle {{
        background: transparent;
        border: 0;
    }}
    QSplitter::handle:horizontal {{
        margin: 4px 1px;
        border-radius: 1px;
        background: transparent;
    }}
    QSplitter::handle:horizontal:hover {{ background: transparent; }}
    QSplitter::handle:horizontal:pressed {{ background: transparent; }}
    QSplitter::handle:vertical {{
        margin: 1px 4px;
        border-radius: 1px;
        background: transparent;
    }}
    QSplitter::handle:vertical:hover {{ background: transparent; }}
    QSplitter::handle:vertical:pressed {{ background: transparent; }}
    """
    appended = str(qss_append or "").strip()
    return css + ("\n" + appended if appended else "")


def build_asset_graph_stylesheet(tokens: dict[str, Any] | None = None) -> str:
    merged = _deep_merge(DEFAULT_THEME_TOKENS, tokens or {})
    palette = merged["palette"]
    typography = merged["typography"]
    graph_bg = palette.get("graph_bg", palette["input_bg"])
    graph_text = palette.get("graph_text", palette["text_strong"])
    graph_line = palette.get("graph_line", palette["border_soft"])
    return f""":root {{
  --graph-bg: {graph_bg};
  --graph-text: {graph_text};
  --graph-line: {graph_line};
}}

html,
body {{
  background: var(--graph-bg);
  color: var(--graph-text);
  font-family: {typography['ui_family']};
  height: 100%;
  margin: 0;
  overflow: hidden;
}}

#graph {{
  background: var(--graph-bg);
  border-radius: 0;
  height: 100vh;
  outline: 1px solid transparent;
  width: 100vw;
}}
"""


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
