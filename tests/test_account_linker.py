"""Tests for deterministic Home Assistant account linking."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from custom_components.openid.account_linker import (
    AccountLinkError,
    async_resolve_user,
)


@pytest.mark.asyncio
async def test_link_failure_does_not_create_another_user() -> None:
    """A selected account link failure is terminal and fails closed."""
    credentials = SimpleNamespace(is_new=True)
    existing_user = SimpleNamespace(
        id="existing",
        credentials=[
            SimpleNamespace(
                auth_provider_type="homeassistant",
                data={"username": "user@example.com"},
            )
        ],
    )
    auth = SimpleNamespace(
        async_get_user_by_credentials=AsyncMock(return_value=None),
        async_get_users=AsyncMock(return_value=[existing_user]),
        async_link_user=AsyncMock(side_effect=ValueError("cannot link")),
        async_get_or_create_user=AsyncMock(),
    )
    hass = SimpleNamespace(auth=auth)

    with pytest.raises(AccountLinkError, match="could not be linked"):
        await async_resolve_user(
            hass,
            credentials=credentials,
            credential_data={"username": "user@example.com"},
            create_user=True,
        )

    auth.async_get_or_create_user.assert_not_awaited()
