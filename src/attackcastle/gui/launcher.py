from __future__ import annotations

import sys


def main() -> int:
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
