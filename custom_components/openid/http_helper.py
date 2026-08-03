"""Patch the built-in /auth/authorize and /auth/login_flow pages to load our JS helper."""

import base64
from http import HTTPStatus
from ipaddress import IPv4Address, IPv6Address, ip_address
import json
import logging
from pathlib import Path
from collections.abc import Callable
from urllib.parse import urlencode

from aiohttp.web import FileResponse, Request, Response

from homeassistant.core import HomeAssistant

from .config_helpers import get_active_config
from .const import CONF_BLOCK_LOGIN, CONF_OPENID_TEXT, CONF_TRUSTED_IPS
from .http_security import redirect_response

_LOGGER = logging.getLogger(__name__)

type RequestIP = IPv4Address | IPv6Address


def _read_file_content(path: Path) -> str:
    """Read file content."""
    with path.open(encoding="utf-8") as f:
        return f.read()


def _extract_request_ip(request: Request) -> RequestIP | None:
    """Return the client IP established by Home Assistant HTTP middleware."""
    if not request.remote:
        return None

    candidate = request.remote.split("%", 1)[0]
    try:
        return ip_address(candidate)
    except ValueError:
        _LOGGER.warning("Unable to parse effective request IP")
        return None


def _is_trusted_request(request: Request, config: dict) -> bool:
    """Return whether the request client IP matches a trusted network."""
    if not (ip_obj := _extract_request_ip(request)):
        return False

    return any(ip_obj in network for network in config.get(CONF_TRUSTED_IPS, []))


def override_authorize_login_flow(hass: HomeAssistant) -> Callable[[], None] | None:
    """Patch the built-in /auth/login_flow page to not return any actual login data."""

    _original_post_function = None

    async def post(request: Request) -> Response:
        config = get_active_config(hass)
        if config is None:
            return await _original_post_function(request)

        is_trusted = _is_trusted_request(request, config)
        should_block = config.get(CONF_BLOCK_LOGIN, False) and not is_trusted

        if not should_block:
            content = json.loads((await _original_post_function(request)).text)
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

        return Response(
            status=HTTPStatus.OK,
            body=json.dumps(content),
            content_type="application/json",
        )

    # Swap out the existing GET handler on /auth/authorize
    for resource in hass.http.app.router._resources:  # noqa: SLF001
        if getattr(resource, "canonical", None) == "/auth/login_flow":
            post_handler = resource._routes.get("POST")  # noqa: SLF001
            if post_handler is None:
                return None
            original_routes = dict(resource._routes)  # noqa: SLF001
            _original_post_function = post_handler._handler  # noqa: SLF001
            post_handler._handler = post  # noqa: SLF001
            resource._routes = {"POST": post_handler}  # noqa: SLF001
            _LOGGER.debug("Overrode /auth/login_flow route")

            def restore() -> None:
                post_handler._handler = _original_post_function  # noqa: SLF001
                resource._routes = original_routes  # noqa: SLF001
                _LOGGER.debug("Restored /auth/login_flow route")

            return restore

    _LOGGER.warning("Unable to find /auth/login_flow route to patch")
    return None


def override_authorize_route(hass: HomeAssistant) -> Callable[[], None] | None:
    """Patch the built-in /auth/authorize page to redirect to OpenID authorize with state preserved."""

    _original_get_function = None

    async def get(request: Request) -> Response:
        config = get_active_config(hass)
        if config is None:
            return await _original_get_function(request)

        is_trusted = _is_trusted_request(request, config)
        should_block = config.get(CONF_BLOCK_LOGIN, False) and not is_trusted

        if not should_block:
            response = await _original_get_function(request)
            if isinstance(response, FileResponse):
                path = response._path  # noqa: SLF001
                try:
                    text = await hass.async_add_executor_job(_read_file_content, path)
                    text = text.replace(
                        "</body>", '<script src="/openid/authorize.js"></script></body>'
                    )
                    return Response(text=text, content_type="text/html")
                except (OSError, UnicodeDecodeError):
                    _LOGGER.warning("Failed to inject authorize.js", exc_info=True)
            return response

        params = dict(request.query)


        base_url = f"{request.scheme}://{request.host}"
        params["base_url"] = base_url

        if "state" in params:
            params["client_state"] = params["state"]

        if "client_id" not in params and "state" in params:
            try:
                state = params["state"]
                decoded = base64.b64decode(state).decode("utf-8")
                state_json = json.loads(decoded)
                if "clientId" in state_json:
                    params["client_id"] = state_json["clientId"].rstrip("/")
            except (ValueError, TypeError, json.JSONDecodeError):
                _LOGGER.warning("Failed to extract client_id from state", exc_info=True)

        query_string = urlencode(params)
        redirect_url = f"/auth/openid/authorize?{query_string}"


        return redirect_response(redirect_url)

    # Swap out the existing GET handler on /auth/authorize
    for resource in hass.http.app.router._resources:  # noqa: SLF001
        if getattr(resource, "canonical", None) == "/auth/authorize":
            get_handler = resource._routes.get("GET")  # noqa: SLF001
            if get_handler is None:
                return None
            original_routes = dict(resource._routes)  # noqa: SLF001
            _original_get_function = get_handler._handler  # noqa: SLF001
            get_handler._handler = get  # noqa: SLF001
            resource._routes = {"GET": get_handler}  # noqa: SLF001
            _LOGGER.debug("Overrode /auth/authorize route – custom JS injected")

            def restore() -> None:
                get_handler._handler = _original_get_function  # noqa: SLF001
                resource._routes = original_routes  # noqa: SLF001
                _LOGGER.debug("Restored /auth/authorize route")

            return restore

    _LOGGER.warning("Unable to find /auth/authorize route to patch")
    return None
