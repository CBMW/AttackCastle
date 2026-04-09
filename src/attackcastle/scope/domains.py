from __future__ import annotations

from attackcastle.scope.expansion import is_ip_literal

# Common multi-label public suffixes that require three labels to recover the
# registrable domain (for example, app.example.com.au -> example.com.au).
MULTI_LABEL_PUBLIC_SUFFIXES = frozenset(
    {
        "ac.nz",
        "asn.au",
        "co.in",
        "co.jp",
        "co.kr",
        "co.nz",
        "co.uk",
        "co.za",
        "com.ar",
        "com.au",
        "com.br",
        "com.cn",
        "com.hk",
        "com.mx",
        "com.my",
        "com.sg",
        "com.tr",
        "edu.au",
        "edu.cn",
        "gov.au",
        "gov.nz",
        "gov.uk",
        "id.au",
        "net.au",
        "net.cn",
        "net.nz",
        "org.au",
        "org.cn",
        "org.nz",
        "org.uk",
    }
)


def canonical_hostname(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip().lower().rstrip(".")
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    return cleaned or None


def registrable_domain(hostname: str | None) -> str | None:
    normalized = canonical_hostname(hostname)
    if not normalized or is_ip_literal(normalized):
        return normalized

    labels = [item for item in normalized.split(".") if item]
    if len(labels) < 2:
        return normalized

    suffix = ".".join(labels[-2:])
    if suffix in MULTI_LABEL_PUBLIC_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
