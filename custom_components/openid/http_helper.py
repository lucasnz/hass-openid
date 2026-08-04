"""Compatibility adapter for Home Assistant authentication routes."""

from __future__ import annotations

import base64
from collections.abc import Callable
from http import HTTPStatus
from ipaddress import IPv4Address, IPv6Address, ip_address
import json
import logging
from pathlib import Path
from urllib.parse import urlencode

from aiohttp.web import FileResponse, Request, Response

from homeassistant.core import HomeAssistant

from .config_helpers import get_active_config
from .const import CONF_BLOCK_LOGIN, CONF_OPENID_TEXT, CONF_TRUSTED_IPS
from .http_security import NO_STORE_HEADERS, redirect_response

_LOGGER = logging.getLogger(__name__)

type RequestIP = IPv4Address | IPv6Address


def _read_file_content(path: Path) -> str:
    """Read file content."""
    return path.read_text(encoding="utf-8")


def _extract_request_ip(request: Request) -> RequestIP | None:
    """Return the client IP established by Home Assistant middleware."""
    if not request.remote:
        return None
    candidate = request.remote.split("%", 1)[0]
    try:
        return ip_address(candidate)
    except ValueError:
        _LOGGER.warning("Unable to parse effective request IP")
        return None


def _is_trusted_request(request: Request, config: dict) -> bool:
    """Return whether the client IP matches a configured trusted network."""
    if not (ip_obj := _extract_request_ip(request)):
        return False
    return any(ip_obj in network for network in config.get(CONF_TRUSTED_IPS, []))


def override_authorize_login_flow(hass: HomeAssistant) -> Callable[[], None] | None:
    """Patch /auth/login_flow while retaining every original HTTP method."""
    for resource in hass.http.app.router._resources:  # noqa: SLF001
        if getattr(resource, "canonical", None) != "/auth/login_flow":
            continue
        post_handler = resource._routes.get("POST")  # noqa: SLF001
        original_handler = getattr(post_handler, "_handler", None)
        if post_handler is None or not callable(original_handler):
            return None

        async def post(request: Request) -> Response:
            config = get_active_config(hass)
            if config is None:
                return await original_handler(request)

            should_block = config.get(CONF_BLOCK_LOGIN, False) and not _is_trusted_request(
                request, config
            )
            response_status = HTTPStatus.OK
            response_headers: dict[str, str] = {}
            if not should_block:
                original = await original_handler(request)
                if not isinstance(original, Response) or not isinstance(
                    original.text, str
                ):
                    _LOGGER.warning(
                        "Home Assistant /auth/login_flow returned an unsupported "
                        "response type; leaving it unchanged"
                    )
                    return original
                try:
                    content = json.loads(original.text)
                except (TypeError, json.JSONDecodeError):
                    _LOGGER.warning(
                        "Home Assistant /auth/login_flow returned invalid JSON; "
                        "leaving it unchanged"
                    )
                    return original
                if not isinstance(content, dict):
                    _LOGGER.warning(
                        "Home Assistant /auth/login_flow returned a non-object "
                        "JSON response; leaving it unchanged"
                    )
                    return original
                response_status = original.status
                response_headers = dict(original.headers)
                for header in (
                    "Content-Length",
                    "Content-Encoding",
                    "Content-Type",
                    "ETag",
                    "Last-Modified",
                ):
                    response_headers.pop(header, None)
            else:
                content = {
                    "type": "form",
                    "flow_id": None,
                    "handler": [None],
                    "data_schema": [],
                    "errors": {},
                    "description_placeholders": None,
                    "last_step": None,
                    "preview": None,
                    "step_id": "init",
                }

            content[CONF_BLOCK_LOGIN] = should_block
            content[CONF_OPENID_TEXT] = config.get(
                CONF_OPENID_TEXT, "OpenID / OAuth2 Authentication"
            )
            response_headers.update(NO_STORE_HEADERS)
            return Response(
                status=response_status,
                text=json.dumps(content, separators=(",", ":")),
                content_type="application/json",
                headers=response_headers,
            )

        post_handler._handler = post  # noqa: SLF001
        _LOGGER.debug("Overrode /auth/login_flow route")

        def restore() -> None:
            if post_handler._handler is post:  # noqa: SLF001
                post_handler._handler = original_handler  # noqa: SLF001
                _LOGGER.debug("Restored /auth/login_flow route")
            else:
                _LOGGER.warning(
                    "/auth/login_flow changed after OpenID setup; leaving the "
                    "newer handler in place"
                )

        return restore

    _LOGGER.warning("Unable to find /auth/login_flow route to patch")
    return None


def override_authorize_route(hass: HomeAssistant) -> Callable[[], None] | None:
    """Patch /auth/authorize while retaining every original HTTP method."""
    for resource in hass.http.app.router._resources:  # noqa: SLF001
        if getattr(resource, "canonical", None) != "/auth/authorize":
            continue
        get_handler = resource._routes.get("GET")  # noqa: SLF001
        original_handler = getattr(get_handler, "_handler", None)
        if get_handler is None or not callable(original_handler):
            return None

        async def get(request: Request) -> Response:
            config = get_active_config(hass)
            if config is None:
                return await original_handler(request)

            should_block = config.get(CONF_BLOCK_LOGIN, False) and not _is_trusted_request(
                request, config
            )
            if not should_block:
                response = await original_handler(request)
                if isinstance(response, FileResponse):
                    try:
                        text = await hass.async_add_executor_job(
                            _read_file_content, response._path  # noqa: SLF001
                        )
                        text = text.replace(
                            "</body>",
                            '<script src="/openid/authorize.js"></script></body>',
                        )
                        headers = dict(response.headers)
                        for header in (
                            "Content-Length",
                            "Content-Encoding",
                            "ETag",
                            "Last-Modified",
                        ):
                            headers.pop(header, None)
                        headers.update(NO_STORE_HEADERS)
                        return Response(
                            text=text,
                            content_type="text/html",
                            charset="utf-8",
                            headers=headers,
                        )
                    except (OSError, UnicodeDecodeError):
                        _LOGGER.warning(
                            "Failed to inject authorize.js", exc_info=True
                        )
                return response

            params = dict(request.query)
            if "state" in params:
                params["client_state"] = params["state"]

            encoded_state = params.get("state")
            if "client_id" not in params and encoded_state and len(encoded_state) <= 4096:
                try:
                    decoded = base64.b64decode(encoded_state, validate=True).decode()
                    state_json = json.loads(decoded)
                    client_id = state_json.get("clientId") if isinstance(state_json, dict) else None
                    if isinstance(client_id, str) and client_id:
                        params["client_id"] = client_id.rstrip("/")
                except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
                    _LOGGER.debug("Unable to extract a client ID from opaque state")

            return redirect_response(
                f"/auth/openid/authorize?{urlencode(params)}"
            )

        get_handler._handler = get  # noqa: SLF001
        _LOGGER.debug("Overrode /auth/authorize route")

        def restore() -> None:
            if get_handler._handler is get:  # noqa: SLF001
                get_handler._handler = original_handler  # noqa: SLF001
                _LOGGER.debug("Restored /auth/authorize route")
            else:
                _LOGGER.warning(
                    "/auth/authorize changed after OpenID setup; leaving the newer handler in place"
                )

        return restore

    _LOGGER.warning("Unable to find /auth/authorize route to patch")
    return None
