"""Tests for atomic installation and restoration of runtime patches."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from homeassistant.auth import InvalidAuthError, InvalidProvider

import custom_components.openid as openid
from custom_components.openid.const import DOMAIN


def _fake_hass():
    original_remove = MagicMock(name="original_remove_refresh_token")
    original_create = MagicMock(name="original_create_access_token")
    hass = SimpleNamespace(
        data={},
        auth=SimpleNamespace(
            async_remove_refresh_token=original_remove,
            async_create_access_token=original_create,
        ),
    )
    return hass, original_remove, original_create


def test_runtime_patch_failure_rolls_back_first_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing second route restores the first route and changes no auth method."""
    hass, original_remove, original_create = _fake_hass()
    restored: list[str] = []

    monkeypatch.setattr(
        openid,
        "override_authorize_route",
        lambda _hass: lambda: restored.append("authorize"),
    )
    monkeypatch.setattr(
        openid,
        "override_authorize_login_flow",
        lambda _hass: None,
    )

    with pytest.raises(RuntimeError, match="/auth/login_flow"):
        openid._activate_runtime_patches(hass)

    assert restored == ["authorize"]
    assert hass.auth.async_remove_refresh_token is original_remove
    assert hass.auth.async_create_access_token is original_create
    assert not hass.data[DOMAIN].get("_runtime_patches_active")


def test_runtime_restore_continues_after_one_callback_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every patch gets a restoration attempt even if one restore raises."""
    hass, original_remove, original_create = _fake_hass()
    restored: list[str] = []

    def restore_authorize() -> None:
        restored.append("authorize")

    def restore_login() -> None:
        restored.append("login")
        raise RuntimeError("simulated restore failure")

    monkeypatch.setattr(
        openid,
        "override_authorize_route",
        lambda _hass: restore_authorize,
    )
    monkeypatch.setattr(
        openid,
        "override_authorize_login_flow",
        lambda _hass: restore_login,
    )

    openid._activate_runtime_patches(hass)
    assert hass.auth.async_remove_refresh_token is not original_remove
    assert hass.auth.async_create_access_token is not original_create

    openid._restore_runtime_patches(hass)

    assert restored == ["login", "authorize"]
    assert hass.auth.async_remove_refresh_token is original_remove
    assert hass.auth.async_create_access_token is original_create
    assert not hass.data[DOMAIN].get("_runtime_patches_active")


def test_unavailable_provider_refresh_token_is_revoked_and_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A token from a removed auth provider becomes invalid authentication."""
    hass, original_remove, original_create = _fake_hass()
    original_create.side_effect = InvalidProvider(
        "Auth provider auth_oidc, default not available"
    )
    monkeypatch.setattr(
        openid,
        "override_authorize_route",
        lambda _hass: lambda: None,
    )
    monkeypatch.setattr(
        openid,
        "override_authorize_login_flow",
        lambda _hass: lambda: None,
    )

    openid._activate_runtime_patches(hass)
    stale_token = SimpleNamespace(
        credential=SimpleNamespace(
            auth_provider_type=DOMAIN,
            auth_provider_id="default",
        )
    )

    with pytest.raises(
        InvalidAuthError,
        match="Authentication provider is no longer available",
    ):
        hass.auth.async_create_access_token(stale_token, "192.168.10.14")

    original_remove.assert_called_once_with(stale_token)
    openid._restore_runtime_patches(hass)
    assert hass.auth.async_create_access_token is original_create
    assert hass.auth.async_remove_refresh_token is original_remove


def test_unavailable_non_openid_provider_keeps_core_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The compatibility patch must not alter other providers' failures."""
    hass, original_remove, original_create = _fake_hass()
    original_create.side_effect = InvalidProvider("provider unavailable")
    monkeypatch.setattr(openid, "override_authorize_route", lambda _hass: lambda: None)
    monkeypatch.setattr(openid, "override_authorize_login_flow", lambda _hass: lambda: None)
    openid._activate_runtime_patches(hass)
    token = SimpleNamespace(
        credential=SimpleNamespace(
            auth_provider_type="other_provider", auth_provider_id="default"
        )
    )
    with pytest.raises(InvalidProvider):
        hass.auth.async_create_access_token(token, "192.0.2.1")
    original_remove.assert_not_called()
