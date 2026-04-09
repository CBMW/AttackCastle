from __future__ import annotations

from typing import Any


SERVICE_KNOWLEDGE: dict[str, dict[str, Any]] = {
    "apache": {
        "cpe": "cpe:2.3:a:apache:http_server",
        "cves": ["CVE-2023-25690", "CVE-2021-41773"],
    },
    "nginx": {
        "cpe": "cpe:2.3:a:nginx:nginx",
        "cves": ["CVE-2021-23017"],
    },
    "openssh": {
        "cpe": "cpe:2.3:a:openbsd:openssh",
        "cves": ["CVE-2024-6387"],
    },
    "mysql": {
        "cpe": "cpe:2.3:a:mysql:mysql",
        "cves": ["CVE-2023-21980"],
    },
    "postgresql": {
        "cpe": "cpe:2.3:a:postgresql:postgresql",
        "cves": ["CVE-2023-39417"],
    },
}

TECH_KNOWLEDGE: dict[str, dict[str, Any]] = {
    "wordpress": {
        "cpe": "cpe:2.3:a:wordpress:wordpress",
        "cves": ["CVE-2024-1071"],
    },
    "drupal": {
        "cpe": "cpe:2.3:a:drupal:drupal",
        "cves": ["CVE-2023-48776"],
    },
    "joomla": {
        "cpe": "cpe:2.3:a:joomla:joomla!",
        "cves": ["CVE-2023-23752"],
    },
    "php": {
        "cpe": "cpe:2.3:a:php:php",
        "cves": ["CVE-2024-4577"],
    },
}


def enrich_service_signature(name: str, banner: str | None = None) -> dict[str, Any] | None:
    corpus = " ".join([name or "", banner or ""]).lower()
    for token, payload in SERVICE_KNOWLEDGE.items():
        if token in corpus:
            return {"token": token, **payload}
    return None


def enrich_technology_signature(name: str, version: str | None = None) -> dict[str, Any] | None:
    corpus = " ".join([name or "", version or ""]).lower()
    for token, payload in TECH_KNOWLEDGE.items():
        if token in corpus:
            return {"token": token, **payload}
    return None

