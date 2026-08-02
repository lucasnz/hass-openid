"""Identity normalization helpers for the OpenID integration."""

from __future__ import annotations


def normalize_username(value: object) -> str:
    """Validate and return the canonical username used for account matching."""
    if not isinstance(value, str):
        raise ValueError("username claim must be a string")

    username = value.strip()
    if not username:
        raise ValueError("username claim must not be empty")

    return username.casefold()
