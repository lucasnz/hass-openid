"""Tests for OpenID authorization and identity handling."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp.test_utils import make_mocked_request
from yarl import URL

from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant

from custom_components.openid import views
from custom_components.openid.const import (
    CONF_BLOCK_LOGIN,
    CONF_CREATE_USER,
    CONF_SCOPE,
    CONF_TOKEN_URL,
    CONF_USE_HEADER_AUTH,
    CONF_USER_INFO_URL,
    CONF_USERNAME_FIELD,
    CONF_VALIDATE_TLS,
    CRED_LOGOUT_REDIRECT_URI,
    DOMAIN,
)
from custom_components.openid.identity import normalize_username
from custom_components.openid.views import OpenIDAuthorizeView, OpenIDCallbackView


@pytest.mark.asyncio
async def test_callback_url_builder_remains_static(hass: HomeAssistant) -> None:
    """Calling the callback builder through an instance must not bind self."""
    assert isinstance(
        OpenIDCallbackView.__dict__["_build_callback_url"], staticmethod
    )

    callback_url = OpenIDCallbackView(hass)._build_callback_url(
        "https://ha.example/auth/external/callback",
        "authorization-code",
        "client-state",
    )
    query = URL(callback_url).query

    assert query["code"] == "authorization-code"
    assert query["state"] == "client-state"
    assert query["auth_callback"] == "1"


def test_url_origin_requires_exact_host_and_effective_port() -> None:
    """A hostname that merely starts with the HA hostname is not trusted."""
    assert views._url_origin("https://ha.example/path") == (
        "https",
        "ha.example",
        443,
    )
    assert views._url_origin("https://ha.example:443/other") == (
        "https",
        "ha.example",
        443,
    )
    assert views._url_origin("https://ha.example.evil.invalid") != views._url_origin(
        "https://ha.example"
    )


def test_consent_skip_uses_exact_origin(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the real Home Assistant origin skips the custom consent page."""
    monkeypatch.setattr(
        views,
        "get_active_config",
        lambda _hass: {CONF_BLOCK_LOGIN: True},
    )
    monkeypatch.setattr(views, "get_url", lambda *_args, **_kwargs: "https://ha.example")
    view = OpenIDAuthorizeView(hass)

    assert not view.should_show_consent_screen(
        {"client_id": "https://ha.example/frontend"}
    )
    assert view.should_show_consent_screen(
        {"client_id": "https://ha.example.evil.invalid/frontend"}
    )


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        ("  MAPPED@Example.COM  ", "mapped@example.com"),
        ("Straße", "strasse"),
    ],
)
def test_normalize_username(raw_value: object, expected: str) -> None:
    """Username claims are stripped and case-folded before matching."""
    assert normalize_username(raw_value) == expected


@pytest.mark.parametrize("raw_value", [None, "", "   ", 123, ["user@example.com"]])
def test_normalize_username_rejects_invalid_claims(raw_value: object) -> None:
    """Missing and non-string username claims are rejected."""
    with pytest.raises(ValueError):
        normalize_username(raw_value)


@pytest.mark.asyncio
async def test_existing_user_lookup_uses_credentials_not_user_name() -> None:
    """Only credential usernames are used to locate an HA account."""
    name_only_user = SimpleNamespace(
        id="name-only",
        name="mapped@example.com",
        credentials=[],
    )
    credential_user = SimpleNamespace(
        id="credential-user",
        name="Unrelated display name",
        credentials=[
            SimpleNamespace(
                auth_provider_type="homeassistant",
                data={"username": "MAPPED@example.com"},
            )
        ],
    )
    hass = SimpleNamespace(
        auth=SimpleNamespace(
            async_get_users=AsyncMock(
                return_value=[name_only_user, credential_user]
            )
        )
    )

    result = await OpenIDCallbackView(hass)._async_find_user_by_username(
        " mapped@EXAMPLE.com "
    )

    assert result is credential_user


@pytest.mark.asyncio
async def test_openid_credential_match_has_priority() -> None:
    """An existing OpenID credential wins over another provider credential."""
    other_provider_user = SimpleNamespace(
        id="other-provider",
        name="Other provider",
        credentials=[
            SimpleNamespace(
                auth_provider_type="homeassistant",
                data={"username": "mapped@example.com"},
            )
        ],
    )
    openid_user = SimpleNamespace(
        id="openid-user",
        name="OpenID user",
        credentials=[
            SimpleNamespace(
                auth_provider_type=DOMAIN,
                data={"username": "mapped@example.com"},
            )
        ],
    )
    hass = SimpleNamespace(
        auth=SimpleNamespace(
            async_get_users=AsyncMock(
                return_value=[other_provider_user, openid_user]
            )
        )
    )

    result = await OpenIDCallbackView(hass)._async_find_user_by_username(
        "mapped@example.com"
    )

    assert result is openid_user


@pytest.mark.asyncio
async def test_existing_user_lookup_rejects_ambiguous_matches() -> None:
    """Two users matching at the same priority are not linked arbitrarily."""
    users = [
        SimpleNamespace(
            id=f"user-{index}",
            name=f"User {index}",
            credentials=[
                SimpleNamespace(
                    auth_provider_type="homeassistant",
                    data={"username": "mapped@example.com"},
                )
            ],
        )
        for index in range(2)
    ]
    hass = SimpleNamespace(
        auth=SimpleNamespace(async_get_users=AsyncMock(return_value=users))
    )

    with pytest.raises(ValueError, match="multiple non-OpenID credentials"):
        await OpenIDCallbackView(hass)._async_find_user_by_username(
            "mapped@example.com"
        )


@pytest.mark.asyncio
async def test_callback_links_existing_user_by_mapped_username(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The callback maps the configured claim and links the matching HA user."""
    credentials = SimpleNamespace(data={}, is_new=True)
    provider = SimpleNamespace(
        async_get_or_create_credentials=AsyncMock(return_value=credentials)
    )
    matching_user = SimpleNamespace(
        id="existing-user",
        name="Unrelated display name",
        credentials=[
            SimpleNamespace(
                auth_provider_type="homeassistant",
                data={"username": "mapped@example.com"},
            )
        ],
        is_owner=False,
        groups=[],
    )
    auth = SimpleNamespace(
        async_get_user_by_credentials=AsyncMock(return_value=None),
        async_get_users=AsyncMock(return_value=[matching_user]),
        async_link_user=AsyncMock(),
        async_get_or_create_user=AsyncMock(),
        async_update_user_credentials_data=MagicMock(),
        async_update_user=AsyncMock(),
    )
    hass = SimpleNamespace(
        auth=auth,
        data={DOMAIN: {"auth_provider": provider}},
    )
    config = {
        CONF_CLIENT_ID: "oidc-client",
        CONF_CLIENT_SECRET: "oidc-secret",
        CONF_TOKEN_URL: "https://idp.example/token",
        CONF_USER_INFO_URL: "https://idp.example/userinfo",
        CONF_SCOPE: "profile email",
        CONF_USERNAME_FIELD: "email",
        CONF_CREATE_USER: False,
        CONF_USE_HEADER_AUTH: True,
        CONF_VALIDATE_TLS: True,
    }
    pending = {
        "client_id": "https://ha.example/",
        "redirect_uri": "https://ha.example/?auth_callback=1",
        "base_url": "https://ha.example",
        "client_state": "client-state",
    }

    monkeypatch.setattr(views, "get_active_config", lambda _hass: config)
    monkeypatch.setattr(
        views,
        "pop_pending",
        lambda _hass, _store, _state: pending,
    )
    monkeypatch.setattr(
        views,
        "_validate_client_request",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        views,
        "exchange_code_for_token",
        AsyncMock(return_value={"access_token": "access-token"}),
    )
    monkeypatch.setattr(
        views,
        "fetch_user_info",
        AsyncMock(
            return_value={
                "email": "  MAPPED@Example.COM  ",
                "name": "Display Name",
                "sub": "subject-1",
            }
        ),
    )
    monkeypatch.setattr(
        views,
        "create_auth_code",
        lambda _hass, _client_id, _credentials: "ha-auth-code",
    )

    request = make_mocked_request(
        "GET",
        "/auth/openid/callback?code=idp-code&state=internal-state",
    )
    response = await OpenIDCallbackView(hass).get(request)

    assert response.status == 302
    callback_query = URL(response.headers["Location"]).query
    assert callback_query["code"] == "ha-auth-code"
    assert callback_query["state"] == "client-state"

    credential_fields = provider.async_get_or_create_credentials.await_args.args[0]
    assert credential_fields["username"] == "mapped@example.com"
    auth.async_link_user.assert_awaited_once_with(matching_user, credentials)
    auth.async_get_or_create_user.assert_not_awaited()


def test_post_logout_redirect_is_only_stored_when_configured() -> None:
    """No implicit post_logout_redirect_uri is persisted."""
    credential_data = {
        CRED_LOGOUT_REDIRECT_URI: "https://old-ha.example/",
    }
    OpenIDCallbackView._store_logout_metadata(
        credential_data,
        {"id_token": "token"},
        {},
        None,
    )
    assert CRED_LOGOUT_REDIRECT_URI not in credential_data

    OpenIDCallbackView._store_logout_metadata(
        credential_data,
        None,
        {},
        "https://ha.example/",
    )
    assert credential_data[CRED_LOGOUT_REDIRECT_URI] == "https://ha.example/"
