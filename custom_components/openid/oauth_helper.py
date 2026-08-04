"""OpenID Connect OAuth helpers for Home Assistant."""

from __future__ import annotations

from base64 import b64encode
import logging
from typing import Any
from urllib.parse import quote_plus

from homeassistant.core import HomeAssistant

from .config_helpers import get_active_config
from .const import CONF_CA_CERT_PATH, CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS
from .network import (
    MAX_TOKEN_BYTES,
    MAX_USERINFO_BYTES,
    async_request_json_object,
)

_LOGGER = logging.getLogger(__name__)


async def exchange_code_for_token(
    hass: HomeAssistant,
    *,
    token_url: str,
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    validate_tls: bool | None = None,
    use_header_auth: bool = True,
    code_verifier: str | None = None,
    ca_cert_path: str | None = None,
) -> dict[str, Any]:
    """Exchange the authorisation code for tokens at the IdP."""
    config = get_active_config(hass) or {}
    if validate_tls is None:
        validate_tls = bool(config.get(CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS))
    ca_cert_path = ca_cert_path or config.get(CONF_CA_CERT_PATH)

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    if code_verifier is not None:
        data["code_verifier"] = code_verifier

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if use_header_auth:
        # RFC 6749 section 2.3.1 requires each component to be form-encoded
        # before joining them with a colon and applying Base64.
        credentials = (
            f"{quote_plus(client_id, safe='')}:{quote_plus(client_secret, safe='')}"
        )
        encoded_credentials = b64encode(credentials.encode()).decode("ascii")
        headers["Authorization"] = f"Basic {encoded_credentials}"
    else:
        _LOGGER.warning(
            "Sending the OpenID client secret in the token request body; "
            "ensure provider request logging is protected"
        )
        data["client_id"] = client_id
        data["client_secret"] = client_secret

    _LOGGER.debug("Exchanging an authorization code at the configured token endpoint")
    return await async_request_json_object(
        hass,
        "POST",
        token_url,
        validate_tls=validate_tls,
        endpoint_name="token endpoint",
        max_bytes=MAX_TOKEN_BYTES,
        headers=headers,
        data=data,
        ca_cert_path=ca_cert_path,
    )


async def fetch_user_info(
    hass: HomeAssistant,
    user_info_url: str,
    access_token: str,
    validate_tls: bool | None = None,
    ca_cert_path: str | None = None,
) -> dict[str, Any]:
    """Fetch user information from the UserInfo endpoint."""
    config = get_active_config(hass) or {}
    if validate_tls is None:
        validate_tls = bool(config.get(CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS))
    ca_cert_path = ca_cert_path or config.get(CONF_CA_CERT_PATH)

    return await async_request_json_object(
        hass,
        "GET",
        user_info_url,
        validate_tls=validate_tls,
        endpoint_name="UserInfo endpoint",
        max_bytes=MAX_USERINFO_BYTES,
        headers={"Authorization": f"Bearer {access_token}"},
        ca_cert_path=ca_cert_path,
    )
