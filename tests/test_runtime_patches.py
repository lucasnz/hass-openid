"""Tests for atomic installation and restoration of runtime patches."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import custom_components.openid as openid
from custom_components.openid.const import DOMAIN


def _fake_hass():
    original_remove = MagicMock(name="original_remove_refresh_token")
    hass = SimpleNamespace(
        data={},
        auth=SimpleNamespace(async_remove_refresh_token=original_remove),
    )
    return hass, original_remove


def test_runtime_patch_failure_rolls_back_first_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing second route restores the first route and changes no auth method."""
    hass, original_remove = _fake_hass()
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
    assert not hass.data[DOMAIN].get("_runtime_patches_active")


def test_runtime_restore_continues_after_one_callback_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every patch gets a restoration attempt even if one restore raises."""
    hass, original_remove = _fake_hass()
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

    openid._restore_runtime_patches(hass)

    assert restored == ["login", "authorize"]
    assert hass.auth.async_remove_refresh_token is original_remove
    assert not hass.data[DOMAIN].get("_runtime_patches_active")
