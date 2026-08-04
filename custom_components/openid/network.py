"""Bounded and validated network helpers for identity-provider traffic."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from functools import partial
from http import HTTPStatus
import json
from pathlib import Path
import ssl
from typing import Any
from ipaddress import ip_address
from urllib.parse import urlsplit

from aiohttp import ClientResponse, ClientTimeout

from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client

DEFAULT_HTTP_TIMEOUT = ClientTimeout(total=15, connect=5, sock_read=10)
MAX_DISCOVERY_BYTES = 512 * 1024
MAX_JWKS_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 256 * 1024
MAX_USERINFO_BYTES = 256 * 1024
_SSL_CONTEXT_CACHE_KEY = "_openid_ssl_contexts"


class ProviderResponseError(RuntimeError):
    """Raised when an identity provider returns an invalid response."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        transient: bool = False,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.transient = transient


async def async_get_ssl_parameter(
    hass: HomeAssistant,
    *,
    validate_tls: bool,
    ca_cert_path: str | None = None,
) -> ssl.SSLContext | bool | None:
    """Return an aiohttp SSL parameter with an optional private CA bundle."""
    if ca_cert_path and not validate_tls:
        raise ValueError(
            "A custom CA certificate cannot be used when TLS validation is disabled"
        )
    if not validate_tls:
        return False
    if not ca_cert_path:
        return None
    if not isinstance(ca_cert_path, str) or not ca_cert_path.strip():
        raise ValueError("Custom CA certificate path is invalid")

    config_dir = Path(hass.config.config_dir).resolve()
    candidate = Path(ca_cert_path.strip())
    if not candidate.is_absolute():
        candidate = config_dir / candidate
    try:
        resolved = await hass.async_add_executor_job(
            partial(candidate.resolve, strict=True)
        )
    except OSError as err:
        raise ValueError("Custom CA certificate file does not exist") from err
    if not resolved.is_relative_to(config_dir):
        raise ValueError(
            "Custom CA certificate must be stored inside the Home Assistant config directory"
        )
    if not await hass.async_add_executor_job(resolved.is_file):
        raise ValueError("Custom CA certificate path must refer to a file")

    stat = await hass.async_add_executor_job(resolved.stat)
    cache: dict[str, dict[str, Any]] = hass.data.setdefault(
        _SSL_CONTEXT_CACHE_KEY, {}
    )
    cache_key = str(resolved)
    cached = cache.get(cache_key)
    fingerprint = (stat.st_mtime_ns, stat.st_size)
    if cached and cached.get("fingerprint") == fingerprint:
        return cached["context"]

    try:
        context = await hass.async_add_executor_job(
            partial(ssl.create_default_context, cafile=str(resolved))
        )
    except (OSError, ssl.SSLError) as err:
        raise ValueError("Custom CA certificate file is invalid") from err
    cache[cache_key] = {"fingerprint": fingerprint, "context": context}
    return context


def validate_provider_url(value: str, *, field: str = "provider URL") -> str:
    """Validate and normalize an absolute HTTPS provider URL.

    Plain HTTP is accepted only for loopback hosts so development providers do
    not require disabling transport security for non-local endpoints.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is missing")

    value = value.strip()
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as err:
        raise ValueError(f"{field} is invalid") from err

    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError(f"{field} must not contain credentials or a fragment")
    if not parsed.hostname or parsed.scheme not in {"http", "https"}:
        raise ValueError(f"{field} must be an absolute HTTP(S) URL")

    hostname = parsed.hostname.rstrip(".").casefold()
    is_loopback = hostname == "localhost"
    if not is_loopback:
        try:
            is_loopback = ip_address(hostname).is_loopback
        except ValueError:
            pass
    if parsed.scheme != "https" and not is_loopback:
        raise ValueError(f"{field} must use HTTPS")

    # Accessing parsed.port validates the numeric range; retain explicit use so
    # static analysers do not treat it as accidental.
    _ = port
    return value


def validate_issuer_url(value: str) -> str:
    """Validate an OIDC issuer identifier."""
    value = validate_provider_url(value, field="issuer")
    parsed = urlsplit(value)
    if parsed.query:
        raise ValueError("issuer must not contain a query")
    # OIDC issuer comparison is exact. In particular, a trailing slash is
    # significant and must not be normalized away.
    return value


async def async_read_json_object(
    response: ClientResponse,
    *,
    max_bytes: int,
    endpoint_name: str,
) -> dict[str, Any]:
    """Read a size-limited JSON object from a provider response."""
    content_type = (
        (response.headers.get("Content-Type") or "")
        .split(";", 1)[0]
        .strip()
        .lower()
    )
    if content_type != "application/json" and not content_type.endswith("+json"):
        raise ProviderResponseError(
            f"{endpoint_name} did not return JSON content"
        )

    content_length = response.content_length
    if content_length is not None and content_length > max_bytes:
        raise ProviderResponseError(f"{endpoint_name} response is too large")

    body = await response.content.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ProviderResponseError(f"{endpoint_name} response is too large")

    try:
        decoded = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise ProviderResponseError(
            f"{endpoint_name} did not return valid JSON"
        ) from err

    if not isinstance(decoded, dict):
        raise ProviderResponseError(f"{endpoint_name} must return a JSON object")
    return decoded


async def async_request_json_object(
    hass: HomeAssistant,
    method: str,
    url: str,
    *,
    validate_tls: bool,
    endpoint_name: str,
    max_bytes: int,
    expected_status: HTTPStatus = HTTPStatus.OK,
    headers: Mapping[str, str] | None = None,
    data: Mapping[str, str] | None = None,
    ca_cert_path: str | None = None,
    response_headers: MutableMapping[str, str] | None = None,
) -> dict[str, Any]:
    """Request a validated provider URL and return a bounded JSON object."""
    url = validate_provider_url(url, field=f"{endpoint_name} URL")
    session = aiohttp_client.async_get_clientsession(hass)
    ssl_parameter = await async_get_ssl_parameter(
        hass,
        validate_tls=validate_tls,
        ca_cert_path=ca_cert_path,
    )
    async with session.request(
        method,
        url,
        headers=headers,
        data=data,
        allow_redirects=False,
        timeout=DEFAULT_HTTP_TIMEOUT,
        ssl=ssl_parameter,
    ) as response:
        if response_headers is not None:
            response_headers.clear()
            response_headers.update(
                {key.casefold(): value for key, value in response.headers.items()}
            )
        if response.status != expected_status:
            raise ProviderResponseError(
                f"{endpoint_name} returned HTTP {response.status}",
                status=response.status,
                transient=(
                    response.status == HTTPStatus.REQUEST_TIMEOUT
                    or response.status == HTTPStatus.TOO_MANY_REQUESTS
                    or response.status >= HTTPStatus.INTERNAL_SERVER_ERROR
                ),
            )
        return await async_read_json_object(
            response,
            max_bytes=max_bytes,
            endpoint_name=endpoint_name,
        )
