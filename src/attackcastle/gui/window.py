from __future__ import annotations

import sys
from typing import Any


def __getattr__(name: str) -> Any:
    if name == "MainWindow":
        from attackcastle.gui.main_window import MainWindow

        return MainWindow
    raise AttributeError(name)


def run() -> int:
    from attackcastle.gui.splash import AttackCastleSplash, StartupPreloader

    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QDialog

    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication.instance() or QApplication(sys.argv)
    splash = AttackCastleSplash()
    splash.show()
    app.processEvents()

    StartupPreloader(splash).run()
    splash.set_status("Preparing project chooser...", 98)

    from attackcastle.gui.dialogs import WorkspaceChooserDialog
    from attackcastle.gui.main_window import MainWindow, _run_workspace_migration
    from attackcastle.gui.profile_store import GuiProfileStore
    from attackcastle.gui.workspace_store import WorkspaceStore

    profile_store = GuiProfileStore()
    workspace_store = WorkspaceStore()

    if workspace_store.migration_required():
        splash.close()
        if not _run_workspace_migration(workspace_store, profile_store):
            return 0
        splash = AttackCastleSplash()
        splash.show()
        app.processEvents()

    workspaces = workspace_store.load_workspaces()
    splash.close()
    chooser = WorkspaceChooserDialog(workspaces, workspace_store.get_active_workspace_id(), workspace_store=workspace_store)
    if chooser.exec() != QDialog.Accepted:
        return 0

    selected_workspace = None
    if chooser.launch_action() == "open_workspace":
        selected_workspace = workspace_store.load_workspace(chooser.selected_workspace_id())
        if selected_workspace is None:
            return 0
        workspace_store.set_active_workspace(selected_workspace.workspace_id)
    elif chooser.launch_action() == "launch_without_workspace":
        workspace_store.set_active_workspace("")
    else:
        return 0

    splash = AttackCastleSplash()
    splash.show()
    splash.set_status("Building AttackCastle workspace...", 99)
    window = MainWindow(store=profile_store, workspace_store=workspace_store, active_workspace=selected_workspace)
    window._apply_restore_geometry()
    window._geometry_synced_to_screen = True
    window.showMaximized()
    splash.close()
    return app.exec()


__all__ = ["MainWindow", "run"]
