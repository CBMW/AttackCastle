from __future__ import annotations

from datetime import datetime, timezone


def cert_name_to_string(parts: tuple[tuple[tuple[str, str], ...], ...] | None) -> str | None:
    if not parts:
        return None
    flattened: list[str] = []
    for seq in parts:
        for key, value in seq:
            flattened.append(f"{key}={value}")
    return ", ".join(flattened) if flattened else None


def parse_not_after(not_after: str | None) -> tuple[str | None, int | None]:
    if not not_after:
        return None, None
    try:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_remaining = int((dt - datetime.now(timezone.utc)).total_seconds() // 86400)
        return dt.isoformat(), days_remaining
    except ValueError:
        return not_after, None

