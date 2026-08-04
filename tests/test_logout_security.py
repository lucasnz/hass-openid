"""Tests for server-side logout ticket creation."""

import json
from types import SimpleNamespace

import pytest
from aiohttp.test_utils import make_mocked_request

from homeassistant.components.http import KEY_HASS_USER
from homeassistant.const import CONF_CLIENT_ID

from custom_components.openid import views
from custom_components.openid.const import (
    CONF_LOGOUT_URL,
    CRED_ID_TOKEN,
    DOMAIN,
)
from custom_components.openid.views import OpenIDSessionView


@pytest.mark.asyncio
async def test_session_endpoint_never_returns_id_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Frontend receives an opaque logout path, not provider token material."""
    credential = SimpleNamespace(
        auth_provider_type=DOMAIN,
        data={CRED_ID_TOKEN: "sensitive-id-token"},
    )
    user = SimpleNamespace(id="user-id", credentials=[credential])
    hass = SimpleNamespace(data={})
    monkeypatch.setattr(
        views,
        "get_active_config",
        lambda _hass: {
            CONF_LOGOUT_URL: "https://idp.example/logout",
            CONF_CLIENT_ID: "client",
        },
    )
    request = make_mocked_request("GET", "/auth/openid/session")
    request[KEY_HASS_USER] = user
    response = await OpenIDSessionView(hass).get(request)
    payload = json.loads(response.text)
    assert response.status == 200
    assert payload["logout_path"].startswith("/auth/openid/logout?ticket=")
    assert "sensitive-id-token" not in response.text
