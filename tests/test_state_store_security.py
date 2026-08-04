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
