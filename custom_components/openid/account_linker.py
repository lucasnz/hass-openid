"""Home Assistant account matching and credential linking."""

from __future__ import annotations

from typing import Any

from homeassistant.auth.models import Credentials, User
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .identity import normalize_username


class AccountLinkError(RuntimeError):
    """Raised when a matching account cannot be safely linked."""


class AmbiguousAccountError(AccountLinkError):
    """Raised when more than one Home Assistant account matches."""


async def async_find_user_by_username(
    hass: HomeAssistant, username: str
) -> User | None:
    """Find one user by credential username, never by display name."""
    normalized_username = normalize_username(username)
    openid_matches: dict[str, User] = {}
    other_matches: dict[str, User] = {}

    for candidate in await hass.auth.async_get_users():
        for existing_credentials in candidate.credentials:
            try:
                stored_username = normalize_username(
                    existing_credentials.data.get("username")
                )
            except ValueError:
                continue
            if stored_username != normalized_username:
                continue
            matches = (
                openid_matches
                if existing_credentials.auth_provider_type == DOMAIN
                else other_matches
            )
            matches[candidate.id] = candidate

    if len(openid_matches) > 1:
        raise AmbiguousAccountError(
            "multiple OpenID credentials match the username"
        )
    if openid_matches:
        return next(iter(openid_matches.values()))
    if len(other_matches) > 1:
        raise AmbiguousAccountError(
            "multiple non-OpenID credentials match the username"
        )
    return next(iter(other_matches.values()), None)


async def async_resolve_user(
    hass: HomeAssistant,
    *,
    credentials: Credentials,
    credential_data: dict[str, Any],
    create_user: bool,
) -> User | None:
    """Return the linked/matched user or create one when explicitly allowed."""
    user = await hass.auth.async_get_user_by_credentials(credentials)
    if user is not None:
        return user

    username = credential_data.get("username")
    existing_user = (
        await async_find_user_by_username(hass, username)
        if isinstance(username, str)
        else None
    )
    if existing_user is not None:
        try:
            await hass.auth.async_link_user(existing_user, credentials)
        except ValueError as err:
            raise AccountLinkError(
                "the matching Home Assistant account could not be linked"
            ) from err
        credentials.is_new = False
        credential_data.setdefault("openid_groups_initialized", True)
        return existing_user

    if not create_user:
        return None
    try:
        return await hass.auth.async_get_or_create_user(credentials)
    except ValueError as err:
        raise AccountLinkError("a Home Assistant user could not be created") from err
