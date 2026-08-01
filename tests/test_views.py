"""Tests for OpenID authorization and identity handling."""

import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from yarl import URL

from homeassistant.components.person import DOMAIN as PERSON_DOMAIN
from homeassistant.core import HomeAssistant

from custom_components.openid import views
from custom_components.openid.auth_provider import OpenIDAuthProvider
from custom_components.openid.const import (
    CONF_BLOCK_LOGIN,
    CRED_LOGOUT_REDIRECT_URI,
)
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


@pytest.mark.asyncio
async def test_existing_user_lookup_uses_mapped_username() -> None:
    """The normalized username claim is used to locate an HA user."""
    matching_user = SimpleNamespace(
        name="mapped@example.com",
        credentials=[],
    )
    display_name_only = SimpleNamespace(
        name="Display Name",
        credentials=[],
    )
    hass = SimpleNamespace(
        auth=SimpleNamespace(
            async_get_users=AsyncMock(
                return_value=[display_name_only, matching_user]
            )
        )
    )

    result = await OpenIDCallbackView(hass)._async_find_user_by_username(
        "MAPPED@example.com"
    )

    assert result is matching_user


@pytest.mark.asyncio
async def test_person_is_never_reassigned_by_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A similarly named Person linked to another user remains untouched."""
    storage = SimpleNamespace(
        async_items=MagicMock(
            return_value=[
                {
                    "id": "mapped-example-com",
                    "name": "mapped@example.com",
                    "user_id": "other-user",
                }
            ]
        ),
        async_update_item=AsyncMock(),
    )
    hass = SimpleNamespace(data={PERSON_DOMAIN: (None, storage, None)})
    create_person = AsyncMock()
    monkeypatch.setattr(views, "async_create_person", create_person)

    await OpenIDCallbackView(hass)._ensure_person_for_user(
        SimpleNamespace(id="openid-user", name="Display Name"),
        {"username": "mapped@example.com", "name": "Display Name"},
    )

    storage.async_update_item.assert_not_awaited()
    create_person.assert_awaited_once_with(
        hass,
        "mapped@example.com",
        user_id="openid-user",
    )


def test_callback_does_not_rewrite_existing_group_membership() -> None:
    """The login callback must not replace an existing user's HA groups."""
    callback_source = inspect.getsource(OpenIDCallbackView.get)

    assert "group_ids=" not in callback_source
    assert "openid_groups_initialized" not in callback_source


@pytest.mark.asyncio
async def test_new_user_name_uses_mapped_username() -> None:
    """Automatically created users use the configured username claim as HA name."""
    credentials = SimpleNamespace(
        data={"username": "mapped@example.com", "name": "Display Name"}
    )

    metadata = await OpenIDAuthProvider.async_user_meta_for_credentials(
        SimpleNamespace(), credentials
    )

    assert metadata.name == "mapped@example.com"


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
