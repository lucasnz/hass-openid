"""Bounded, expiring in-memory state storage for OpenID flows."""

from __future__ import annotations

from time import monotonic
from typing import Any

from homeassistant.core import HomeAssistant

AUTH_STATE_STORE = "_openid_state"
CONSENT_STATE_STORE = "_openid_consent_pending"
ANDROID_STATE_STORE = "_openid_android_callbacks"
LOGOUT_STATE_STORE = "_openid_logout_tickets"
LOGOUT_TOKEN_JTI_STORE = "_openid_logout_token_jti"

AUTH_STATE_TTL = 10 * 60
ANDROID_STATE_TTL = 15 * 60
LOGOUT_STATE_TTL = 60
LOGOUT_TOKEN_JTI_TTL = 24 * 60 * 60
MAX_PENDING_ENTRIES = 256
MAX_STATE_KEY_LENGTH = 512


class StateStoreFull(RuntimeError):
    """Raised when no more pending authentication states can be accepted."""



def _cleanup(store: dict[str, dict[str, Any]], ttl: float) -> None:
    """Remove expired entries from a state store."""
    cutoff = monotonic() - ttl
    for key, entry in list(store.items()):
        if entry.get("created_at", 0.0) < cutoff:
            store.pop(key, None)


def store_pending(
    hass: HomeAssistant,
    store_name: str,
    key: str,
    value: dict[str, Any],
    *,
    ttl: float = AUTH_STATE_TTL,
) -> None:
    """Store a bounded pending entry without evicting an active flow."""
    if not key or len(key) > MAX_STATE_KEY_LENGTH:
        raise ValueError("state key is missing or too long")

    store: dict[str, dict[str, Any]] = hass.data.setdefault(store_name, {})
    _cleanup(store, ttl)

    if key not in store and len(store) >= MAX_PENDING_ENTRIES:
        raise StateStoreFull("too many authentication requests are pending")

    store[key] = {"created_at": monotonic(), "value": dict(value)}


def get_pending(
    hass: HomeAssistant,
    store_name: str,
    key: str,
    *,
    ttl: float = AUTH_STATE_TTL,
) -> dict[str, Any] | None:
    """Return a pending entry when it exists and has not expired."""
    store: dict[str, dict[str, Any]] = hass.data.setdefault(store_name, {})
    _cleanup(store, ttl)
    entry = store.get(key)
    return dict(entry["value"]) if entry else None


def pop_pending(
    hass: HomeAssistant,
    store_name: str,
    key: str,
    *,
    ttl: float = AUTH_STATE_TTL,
) -> dict[str, Any] | None:
    """Remove and return a pending entry when it has not expired."""
    store: dict[str, dict[str, Any]] = hass.data.setdefault(store_name, {})
    _cleanup(store, ttl)
    entry = store.pop(key, None)
    return dict(entry["value"]) if entry else None
