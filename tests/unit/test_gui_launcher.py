from __future__ import annotations

import shlex

from attackcastle.gui import launcher


def test_qtwebengine_root_launch_adds_no_sandbox(monkeypatch) -> None:
    monkeypatch.delenv("QTWEBENGINE_CHROMIUM_FLAGS", raising=False)
    monkeypatch.delenv("QTWEBENGINE_DISABLE_SANDBOX", raising=False)
    monkeypatch.setattr(launcher.os, "geteuid", lambda: 0, raising=False)

    assert launcher.configure_qtwebengine_for_current_process() is True

    assert launcher.os.environ["QTWEBENGINE_DISABLE_SANDBOX"] == "1"
    assert shlex.split(launcher.os.environ["QTWEBENGINE_CHROMIUM_FLAGS"]) == ["--no-sandbox"]


def test_qtwebengine_root_launch_preserves_existing_flags(monkeypatch) -> None:
    monkeypatch.setenv("QTWEBENGINE_CHROMIUM_FLAGS", '--disable-gpu --user-agent="Attack Castle"')
    monkeypatch.delenv("QTWEBENGINE_DISABLE_SANDBOX", raising=False)
    monkeypatch.setattr(launcher.os, "geteuid", lambda: 0, raising=False)

    assert launcher.configure_qtwebengine_for_current_process() is True

    flags = shlex.split(launcher.os.environ["QTWEBENGINE_CHROMIUM_FLAGS"])
    assert flags == ["--disable-gpu", "--user-agent=Attack Castle", "--no-sandbox"]
    assert launcher.os.environ["QTWEBENGINE_DISABLE_SANDBOX"] == "1"


def test_qtwebengine_root_launch_does_not_duplicate_no_sandbox(monkeypatch) -> None:
    monkeypatch.setenv("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu --no-sandbox")
    monkeypatch.delenv("QTWEBENGINE_DISABLE_SANDBOX", raising=False)
    monkeypatch.setattr(launcher.os, "geteuid", lambda: 0, raising=False)

    assert launcher.configure_qtwebengine_for_current_process() is False

    flags = shlex.split(launcher.os.environ["QTWEBENGINE_CHROMIUM_FLAGS"])
    assert flags == ["--disable-gpu", "--no-sandbox"]
    assert launcher.os.environ["QTWEBENGINE_DISABLE_SANDBOX"] == "1"


def test_qtwebengine_non_root_launch_leaves_environment_alone(monkeypatch) -> None:
    monkeypatch.setenv("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu")
    monkeypatch.delenv("QTWEBENGINE_DISABLE_SANDBOX", raising=False)
    monkeypatch.setattr(launcher.os, "geteuid", lambda: 1000, raising=False)

    assert launcher.configure_qtwebengine_for_current_process() is False

    assert launcher.os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] == "--disable-gpu"
    assert "QTWEBENGINE_DISABLE_SANDBOX" not in launcher.os.environ
