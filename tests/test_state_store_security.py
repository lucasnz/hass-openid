"""Tests for bounded authentication state and rate limiting."""

from types import SimpleNamespace

import pytest

from custom_components.openid import state_store


def test_full_store_rejects_new_state_without_eviction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A public request cannot evict another active authentication flow."""
    hass = SimpleNamespace(data={})
    monkeypatch.setattr(state_store, "MAX_PENDING_ENTRIES", 1)
    state_store.store_pending(hass, "test", "first", {"user": "one"})
    with pytest.raises(state_store.StateStoreFull):
        state_store.store_pending(hass, "test", "second", {"user": "two"})
    assert state_store.get_pending(hass, "test", "first") == {"user": "one"}
    assert state_store.get_pending(hass, "test", "second") is None


def test_rate_limit_is_bounded() -> None:
    """Requests beyond the configured sliding-window limit are refused."""
    hass = SimpleNamespace(data={})
    assert state_store.check_rate_limit(hass, "client", limit=2, window=60)
    assert state_store.check_rate_limit(hass, "client", limit=2, window=60)
    assert not state_store.check_rate_limit(hass, "client", limit=2, window=60)


def test_rate_limit_cleanup_uses_each_keys_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Global cleanup must not apply a new endpoint's window to old keys."""
    now = 0.0
    monkeypatch.setattr(state_store, "monotonic", lambda: now)
    monkeypatch.setattr(state_store, "MAX_RATE_LIMIT_KEYS", 2)
    hass = SimpleNamespace(data={})

    assert state_store.check_rate_limit(hass, "long", limit=5, window=100)
    assert state_store.check_rate_limit(hass, "short", limit=5, window=10)

    now = 20.0
    assert state_store.check_rate_limit(hass, "new", limit=5, window=5)
    store = hass.data[state_store.RATE_LIMIT_STORE]
    assert "long" in store
    assert "short" not in store
    assert "new" in store


def test_invalid_rate_limit_configuration_fails_closed() -> None:
    """Invalid limiter parameters cannot accidentally allow traffic."""
    hass = SimpleNamespace(data={})
    assert not state_store.check_rate_limit(hass, "", limit=1, window=60)
    assert not state_store.check_rate_limit(hass, "client", limit=0, window=60)
    assert not state_store.check_rate_limit(hass, "client", limit=1, window=0)
