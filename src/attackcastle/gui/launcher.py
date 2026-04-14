from __future__ import annotations

import os
import shlex
import sys

_QTWEBENGINE_CHROMIUM_FLAGS = "QTWEBENGINE_CHROMIUM_FLAGS"
_QTWEBENGINE_DISABLE_SANDBOX = "QTWEBENGINE_DISABLE_SANDBOX"
_NO_SANDBOX_FLAG = "--no-sandbox"


def _running_as_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return callable(geteuid) and geteuid() == 0


def _chromium_flags() -> list[str]:
    raw_flags = os.environ.get(_QTWEBENGINE_CHROMIUM_FLAGS, "")
    if not raw_flags.strip():
        return []
    try:
        return shlex.split(raw_flags)
    except ValueError:
        return raw_flags.split()


def _set_chromium_flags(flags: list[str]) -> None:
    os.environ[_QTWEBENGINE_CHROMIUM_FLAGS] = shlex.join(flags)


def configure_qtwebengine_for_current_process() -> bool:
    if not _running_as_root():
        return False

    os.environ[_QTWEBENGINE_DISABLE_SANDBOX] = "1"
    flags = _chromium_flags()
    if _NO_SANDBOX_FLAG in flags:
        return False
    _set_chromium_flags([*flags, _NO_SANDBOX_FLAG])
    return True


def main() -> int:
    if configure_qtwebengine_for_current_process():
        sys.stderr.write(
            "AttackCastle GUI is running as root; enabling QtWebEngine's required "
            "--no-sandbox flag for this session.\n"
        )
    try:
        from attackcastle.gui.window import run
    except ImportError as exc:
        message = (
            "PySide6 is required to launch the AttackCastle GUI. "
            "Install the optional GUI dependencies first."
        )
        sys.stderr.write(f"{message}\nImport error: {exc}\n")
        return 1
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
