from __future__ import annotations

import importlib
from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QApplication, QFrame, QLabel, QProgressBar, QVBoxLayout, QWidget


SPLASH_LOGO_PATH = Path(__file__).resolve().parents[1] / "assets" / "splash_logo_template.png"
_WEBENGINE_WARMUP_WIDGETS: list[QWidget] = []


class AttackCastleSplash(QWidget):
    def __init__(self) -> None:
        super().__init__(None, Qt.WindowType.SplashScreen | Qt.WindowType.FramelessWindowHint)
        self.setObjectName("attackCastleSplash")
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.setFixedSize(560, 360)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        panel = QFrame()
        panel.setObjectName("splashPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(34, 30, 34, 28)
        layout.setSpacing(14)

        self.logo_label = QLabel()
        self.logo_label.setObjectName("splashLogo")
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._load_logo()

        self.title_label = QLabel("Welcome to Attack Castle")
        self.title_label.setObjectName("splashTitle")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setWordWrap(True)

        self.status_label = QLabel("Starting GUI...")
        self.status_label.setObjectName("splashStatus")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setWordWrap(True)

        self.progress = QProgressBar()
        self.progress.setObjectName("splashProgress")
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)

        layout.addStretch(1)
        layout.addWidget(self.logo_label)
        layout.addWidget(self.title_label)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress)
        layout.addStretch(1)
        root.addWidget(panel)
        self.setStyleSheet(
            """
            QWidget#attackCastleSplash {
                background: #111827;
                border: 1px solid #334155;
            }
            QFrame#splashPanel {
                background: #111827;
            }
            QLabel#splashLogo {
                min-height: 116px;
            }
            QLabel#splashTitle {
                color: #f8fafc;
                font-size: 26px;
                font-weight: 700;
            }
            QLabel#splashStatus {
                color: #cbd5e1;
                font-size: 13px;
            }
            QProgressBar#splashProgress {
                background: #1f2937;
                border: 1px solid #475569;
                border-radius: 4px;
                height: 8px;
            }
            QProgressBar#splashProgress::chunk {
                background: #38bdf8;
                border-radius: 3px;
            }
            """
        )

    def _load_logo(self) -> None:
        pixmap = QPixmap(str(SPLASH_LOGO_PATH))
        if pixmap.isNull():
            self.logo_label.setText("Attack Castle")
            self.logo_label.setStyleSheet("color: #f8fafc; font-size: 30px; font-weight: 700;")
            return
        scaled = pixmap.scaled(
            128,
            128,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.logo_label.setPixmap(scaled)

    def set_status(self, message: str, progress: int) -> None:
        self.status_label.setText(message)
        self.progress.setValue(max(0, min(progress, 100)))
        QApplication.processEvents()


class StartupPreloader:
    def __init__(self, splash: AttackCastleSplash | None = None) -> None:
        self.splash = splash
        self._web_warmup_view = None

    def status(self, message: str, progress: int) -> None:
        if self.splash is not None:
            self.splash.set_status(message, progress)

    def run(self) -> None:
        steps: list[tuple[str, int, Callable[[], None]]] = [
            ("Loading GUI modules...", 12, self._preload_gui_modules),
            ("Preparing profiles and extensions...", 30, self._preload_stores),
            ("Reading static scan configuration...", 46, self._preload_config_profiles),
            ("Checking scanner readiness cache...", 60, self._preload_readiness),
            ("Preparing report engine...", 72, self._preload_reports),
            ("Warming embedded browser components...", 86, self._preload_webengine),
        ]
        for message, progress, callback in steps:
            self.status(message, progress)
            try:
                callback()
            except Exception:
                # Startup preloading must never block normal GUI launch.
                continue
        self.status("Finishing startup...", 96)

    def _preload_gui_modules(self) -> None:
        for module_name in (
            "attackcastle.gui.common",
            "attackcastle.gui.dialogs",
            "attackcastle.gui.assets_tab",
            "attackcastle.gui.attacker_tab",
            "attackcastle.gui.asset_graph_view",
            "attackcastle.gui.output_tab",
            "attackcastle.gui.scanner_panel",
            "attackcastle.gui.reports_tab",
            "attackcastle.gui.main_window",
        ):
            importlib.import_module(module_name)
            QApplication.processEvents()

    def _preload_stores(self) -> None:
        from attackcastle.gui.extensions_store import GuiExtensionStore
        from attackcastle.gui.profile_store import GuiProfileStore
        from attackcastle.gui.workspace_store import WorkspaceStore

        profile_store = GuiProfileStore()
        profile_store.load()
        extension_store = GuiExtensionStore()
        extension_store.discover()
        extension_store.get_active_theme_manifest()
        workspace_store = WorkspaceStore()
        workspace_store.load_proxy_settings()
        workspace_store.load_ui_layout("startup", "horizontal")

    def _preload_config_profiles(self) -> None:
        from attackcastle.config_loader import load_config

        for profile in ("standard", "recon", "cautious", "aggressive", "bug_bounty", "external_pentest", "full", "stealth"):
            load_config(profile)
            QApplication.processEvents()

    def _preload_readiness(self) -> None:
        from attackcastle.readiness import external_dependency_rows, missing_dependency_rows

        rows = external_dependency_rows()
        missing_dependency_rows(rows)

    def _preload_reports(self) -> None:
        for module_name in (
            "attackcastle.reporting.builder",
            "attackcastle.reporting.viewmodel",
            "attackcastle.extensions.reports.exporter",
        ):
            importlib.import_module(module_name)
            QApplication.processEvents()

    def _preload_webengine(self) -> None:
        app = QApplication.instance()
        platform_name = app.platformName() if app is not None else ""
        if platform_name in {"offscreen", "minimal"}:
            return
        try:
            from PySide6.QtWebChannel import QWebChannel
            from PySide6.QtWebEngineWidgets import QWebEngineView
            from attackcastle.gui.extensions import build_asset_graph_stylesheet
        except ImportError:
            return

        web_dir = Path(__file__).resolve().parent / "web"
        html = f"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>AttackCastle Warmup</title>
    <style>
{build_asset_graph_stylesheet()}
    </style>
  </head>
  <body>
    <div id="graph"></div>
    <script src="cytoscape.min.js"></script>
    <script src="dagre.min.js"></script>
    <script src="cytoscape-dagre.js"></script>
    <script src="qrc:///qtwebchannel/qwebchannel.js"></script>
    <script src="asset_graph.js"></script>
  </body>
</html>
"""
        self._web_warmup_view = QWebEngineView()
        channel = QWebChannel(self._web_warmup_view.page())
        self._web_warmup_view.page().setWebChannel(channel)
        self._web_warmup_view.resize(1, 1)
        self._web_warmup_view.setHtml(html, QUrl.fromLocalFile(str(web_dir) + "/"))
        _WEBENGINE_WARMUP_WIDGETS.append(self._web_warmup_view)
        QApplication.processEvents()
