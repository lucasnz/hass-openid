"""Bounded and validated network helpers for identity-provider traffic."""

from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
import json
from typing import Any
from urllib.parse import urlsplit

from aiohttp import ClientResponse, ClientTimeout

from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client

DEFAULT_HTTP_TIMEOUT = ClientTimeout(total=15, connect=5, sock_read=10)
MAX_DISCOVERY_BYTES = 512 * 1024
MAX_JWKS_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 256 * 1024
MAX_USERINFO_BYTES = 256 * 1024


class ProviderResponseError(RuntimeError):
    """Raised when an identity provider returns an invalid response."""


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
    loopback_hosts = {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and hostname not in loopback_hosts:
        raise ValueError(f"{field} must use HTTPS")

    # Accessing parsed.port validates the numeric range; retain explicit use so
    # static analysers do not treat it as accidental.
    _ = port
    return value


async def async_read_json_object(
    response: ClientResponse,
    *,
    max_bytes: int,
    endpoint_name: str,
) -> dict[str, Any]:
    """Read a size-limited JSON object from a provider response."""
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
) -> dict[str, Any]:
    """Request a validated provider URL and return a bounded JSON object."""
    url = validate_provider_url(url, field=f"{endpoint_name} URL")
    session = aiohttp_client.async_get_clientsession(hass, verify_ssl=validate_tls)
    async with session.request(
        method,
        url,
        headers=headers,
        data=data,
        allow_redirects=False,
        timeout=DEFAULT_HTTP_TIMEOUT,
    ) as response:
        if response.status != expected_status:
            raise ProviderResponseError(
                f"{endpoint_name} returned HTTP {response.status}"
            )
        return await async_read_json_object(
            response,
            max_bytes=max_bytes,
            endpoint_name=endpoint_name,
        )
