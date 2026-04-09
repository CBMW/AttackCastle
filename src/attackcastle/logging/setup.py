from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any


def _console_log_level(verbosity: int) -> int:
    if verbosity <= 0:
        return logging.WARNING
    if verbosity == 1:
        return logging.INFO
    return logging.DEBUG


class RedactionFilter(logging.Filter):
    _INLINE_SECRET_RE = re.compile(
        r"(?P<key>(token|password|secret|api[_-]?key|passphrase))\s*[:=]\s*(?P<value>[^\s,;]+)",
        re.IGNORECASE,
    )

    def __init__(self, secret_resolver: Any | None = None) -> None:
        super().__init__()
        self.secret_resolver = secret_resolver

    def _redact(self, text: str) -> str:
        redacted = text
        if self.secret_resolver is not None:
            try:
                redacted = self.secret_resolver.redact_text(redacted)
            except Exception:
                pass
        redacted = self._INLINE_SECRET_RE.sub(lambda m: f"{m.group('key')}=[redacted-secret]", redacted)
        return redacted

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            rendered = str(record.msg)
        record.msg = self._redact(str(rendered))
        record.args = ()
        return True


def configure_logger(
    log_file_path: Path,
    verbosity: int = 0,
    secret_resolver: Any | None = None,
) -> logging.Logger:
    logger = logging.getLogger("attackcastle")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)

    redaction_filter = RedactionFilter(secret_resolver=secret_resolver)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(_console_log_level(int(verbosity)))
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    console_handler.addFilter(redaction_filter)

    file_handler = logging.FileHandler(log_file_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    file_handler.addFilter(redaction_filter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.propagate = False
    return logger

