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
    max_entries: int | None = None,
) -> None:
    """Store a bounded pending entry without evicting an active flow."""
    if not key or len(key) > MAX_STATE_KEY_LENGTH:
        raise ValueError("state key is missing or too long")

    store: dict[str, dict[str, Any]] = hass.data.setdefault(store_name, {})
    _cleanup(store, ttl)

    effective_max_entries = (
        MAX_PENDING_ENTRIES if max_entries is None else max_entries
    )
    if effective_max_entries < 1:
        raise ValueError("max_entries must be at least 1")
    if key not in store and len(store) >= effective_max_entries:
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
    entry = store.get(key)
    if entry is None:
        return None
    if entry.get("created_at", 0.0) < monotonic() - ttl:
        store.pop(key, None)
        return None
    return dict(entry["value"])


def pop_pending(
    hass: HomeAssistant,
    store_name: str,
    key: str,
    *,
    ttl: float = AUTH_STATE_TTL,
) -> dict[str, Any] | None:
    """Remove and return a pending entry when it has not expired."""
    store: dict[str, dict[str, Any]] = hass.data.setdefault(store_name, {})
    entry = store.pop(key, None)
    if entry is None or entry.get("created_at", 0.0) < monotonic() - ttl:
        return None
    return dict(entry["value"])

RATE_LIMIT_STORE = "_openid_rate_limits"
MAX_RATE_LIMIT_KEYS = 1024


def _recent_rate_limit_timestamps(
    raw_entry: Any,
    *,
    now: float,
    default_window: float,
) -> tuple[float, list[float]]:
    """Return a normalized rate-limit entry, including legacy list entries."""
    if isinstance(raw_entry, dict):
        stored_window = raw_entry.get("window", default_window)
        raw_timestamps = raw_entry.get("timestamps", [])
    else:
        stored_window = default_window
        raw_timestamps = raw_entry if isinstance(raw_entry, list) else []

    try:
        stored_window = float(stored_window)
    except (TypeError, ValueError):
        stored_window = default_window
    stored_window = max(stored_window, 0.001)
    cutoff = now - stored_window
    timestamps = [
        timestamp
        for timestamp in raw_timestamps
        if isinstance(timestamp, (int, float)) and timestamp >= cutoff
    ]
    return stored_window, timestamps


def check_rate_limit(
    hass: HomeAssistant,
    key: str,
    *,
    limit: int,
    window: float,
) -> bool:
    """Return whether a request is allowed by a bounded sliding window."""
    if not key or limit < 1 or window <= 0:
        return False

    now = monotonic()
    store: dict[str, dict[str, Any] | list[float]] = hass.data.setdefault(
        RATE_LIMIT_STORE, {}
    )
    _stored_window, timestamps = _recent_rate_limit_timestamps(
        store.get(key),
        now=now,
        default_window=window,
    )
    if len(timestamps) >= limit:
        store[key] = {"window": window, "timestamps": timestamps}
        return False

    if key not in store and len(store) >= MAX_RATE_LIMIT_KEYS:
        # A new key is the only case that requires a global cleanup. Use each
        # existing key's own window so unrelated endpoints cannot prematurely
        # expire or retain one another's request history.
        for stored_key, raw_entry in list(store.items()):
            stored_window, recent = _recent_rate_limit_timestamps(
                raw_entry,
                now=now,
                default_window=window,
            )
            if recent:
                store[stored_key] = {
                    "window": stored_window,
                    "timestamps": recent,
                }
            else:
                store.pop(stored_key, None)
        if len(store) >= MAX_RATE_LIMIT_KEYS:
            return False

    timestamps.append(now)
    store[key] = {"window": window, "timestamps": timestamps}
    return True
