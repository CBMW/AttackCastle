from __future__ import annotations

import re
from typing import Any

INJECTABLE_RE = re.compile(r"is vulnerable|parameter .*? appears to be", re.IGNORECASE)
DBMS_RE = re.compile(r"back-end dbms:\s*([^\n\r]+)", re.IGNORECASE)


def parse_sqlmap_output(stdout_text: str, stderr_text: str = "") -> dict[str, Any]:
    combined = "\n".join([stdout_text or "", stderr_text or ""])
    injectable = bool(INJECTABLE_RE.search(combined))
    dbms_match = DBMS_RE.search(combined)
    dbms = dbms_match.group(1).strip() if dbms_match else None
    lines = [
        line.strip()
        for line in combined.splitlines()
        if line.strip()
        and (
            "vulnerable" in line.lower()
            or "payload" in line.lower()
            or "dbms" in line.lower()
            or "parameter" in line.lower()
        )
    ]
    unique_lines: list[str] = []
    for line in lines:
        if line not in unique_lines:
            unique_lines.append(line)
    return {
        "injectable": injectable,
        "dbms": dbms,
        "evidence_lines": unique_lines[:50],
    }
