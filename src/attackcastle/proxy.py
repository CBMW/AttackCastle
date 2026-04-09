from __future__ import annotations

import os
import shlex
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Iterable

PROXY_ENV_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
)


@dataclass(frozen=True, slots=True)
class ProxySettings:
    url: str
    scheme: str
    host: str
    port: int | None
    username: str | None = None
    password: str | None = None

    @property
    def authority(self) -> str:
        if self.port is None:
            return self.host
        return f"{self.host}:{self.port}"

    @property
    def credentials(self) -> str | None:
        if self.username is None:
            return None
        if self.password is None:
            return self.username
        return f"{self.username}:{self.password}"

    @property
    def url_without_credentials(self) -> str:
        return f"{self.scheme}://{self.authority}"

    @property
    def redacted_url(self) -> str:
        if self.username is None:
            return self.url_without_credentials
        return f"{self.scheme}://[redacted-secret]@{self.authority}"


def normalize_proxy_url(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    parsed = urllib.parse.urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("Proxy URL must use http:// or https://.")
    if not parsed.hostname:
        raise ValueError("Proxy URL must include a hostname.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Proxy URL must not include a path, query, or fragment.")

    netloc = parsed.hostname
    if ":" in netloc and not netloc.startswith("["):
        netloc = f"[{netloc}]"
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    if parsed.username is not None:
        userinfo = urllib.parse.quote(parsed.username, safe="")
        if parsed.password is not None:
            userinfo = f"{userinfo}:{urllib.parse.quote(parsed.password, safe='')}"
        netloc = f"{userinfo}@{netloc}"
    return urllib.parse.urlunsplit((scheme, netloc, "", "", ""))


def proxy_settings_from_url(value: str | None) -> ProxySettings | None:
    normalized = normalize_proxy_url(value)
    if normalized is None:
        return None
    parsed = urllib.parse.urlsplit(normalized)
    if not parsed.hostname:
        return None
    return ProxySettings(
        url=normalized,
        scheme=parsed.scheme.lower(),
        host=parsed.hostname,
        port=parsed.port,
        username=parsed.username,
        password=parsed.password,
    )


def build_subprocess_env(proxy_url: str | None, base_env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base_env is None else base_env)
    for key in PROXY_ENV_VARS:
        env.pop(key, None)
    normalized = normalize_proxy_url(proxy_url)
    if not normalized:
        return env
    env["HTTP_PROXY"] = normalized
    env["HTTPS_PROXY"] = normalized
    env["http_proxy"] = normalized
    env["https_proxy"] = normalized
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""
    return env


def build_urllib_opener(
    proxy_url: str | None,
    *,
    https_context: ssl.SSLContext | None = None,
    extra_handlers: Iterable[urllib.request.BaseHandler] | None = None,
) -> urllib.request.OpenerDirector:
    handlers: list[urllib.request.BaseHandler] = []
    normalized = normalize_proxy_url(proxy_url)
    proxy_map = {"http": normalized, "https": normalized} if normalized else {}
    handlers.append(urllib.request.ProxyHandler(proxy_map))
    if https_context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=https_context))
    if extra_handlers:
        handlers.extend(list(extra_handlers))
    return urllib.request.build_opener(*handlers)


def open_url(
    request: urllib.request.Request,
    *,
    timeout: int,
    proxy_url: str | None = None,
    https_context: ssl.SSLContext | None = None,
    extra_handlers: Iterable[urllib.request.BaseHandler] | None = None,
):
    opener = build_urllib_opener(
        proxy_url,
        https_context=https_context,
        extra_handlers=extra_handlers,
    )
    return opener.open(request, timeout=timeout)


def redact_proxy_text(text: str, proxy_url: str | None) -> str:
    settings = proxy_settings_from_url(proxy_url)
    if settings is None:
        return text
    redacted = str(text)
    redacted = redacted.replace(settings.url, settings.redacted_url)
    if settings.credentials:
        redacted = redacted.replace(settings.credentials, "[redacted-secret]")
    if settings.password:
        redacted = redacted.replace(settings.password, "[redacted-secret]")
    return redacted


def redact_command_parts(command: Iterable[str], proxy_url: str | None) -> list[str]:
    return [redact_proxy_text(str(part), proxy_url) for part in command]


def command_text(command: Iterable[str], proxy_url: str | None) -> str:
    redacted = redact_command_parts(command, proxy_url)
    return " ".join(shlex.quote(part) for part in redacted)


def whatweb_proxy_args(proxy_url: str | None) -> list[str]:
    settings = proxy_settings_from_url(proxy_url)
    if settings is None:
        return []
    args = ["--proxy", settings.authority]
    if settings.credentials:
        args.extend(["--proxy-user", settings.credentials])
    return args


def nikto_proxy_args(proxy_url: str | None) -> list[str]:
    settings = proxy_settings_from_url(proxy_url)
    if settings is None:
        return []
    return ["-useproxy", settings.url]


def nuclei_proxy_args(proxy_url: str | None) -> list[str]:
    settings = proxy_settings_from_url(proxy_url)
    if settings is None:
        return []
    return ["-p", settings.url]


def sqlmap_proxy_args(proxy_url: str | None) -> list[str]:
    settings = proxy_settings_from_url(proxy_url)
    if settings is None:
        return []
    args = [f"--proxy={settings.url_without_credentials}"]
    if settings.credentials:
        args.extend(["--proxy-cred", settings.credentials])
    return args


def wpscan_proxy_args(proxy_url: str | None) -> list[str]:
    settings = proxy_settings_from_url(proxy_url)
    if settings is None:
        return []
    args = ["--proxy", settings.url_without_credentials]
    if settings.credentials:
        args.extend(["--proxy-auth", settings.credentials])
    return args


def chromium_proxy_args(proxy_url: str | None) -> list[str]:
    settings = proxy_settings_from_url(proxy_url)
    if settings is None:
        return []
    return [f"--proxy-server={settings.url_without_credentials}"]
