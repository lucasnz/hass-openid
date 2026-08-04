"""Security tests for OpenID credential identity binding."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from custom_components.openid.auth_provider import (
    OpenIDAuthProvider,
    OpenIDIdentityConflictError,
)
from custom_components.openid.const import CRED_ISSUER, CRED_SUBJECT


@pytest.mark.asyncio
async def test_legacy_username_credential_is_bound_once() -> None:
    """A pre-migration username credential acquires issuer and subject once."""
    credential = SimpleNamespace(
        data={"username": "user@example.com"},
        is_new=True,
    )
    provider = SimpleNamespace(
        async_credentials=AsyncMock(return_value=[credential]),
        async_create_credentials=AsyncMock(),
    )
    result = await OpenIDAuthProvider.async_get_or_create_credentials(
        provider,
        {
            "username": "USER@example.com",
            CRED_ISSUER: "https://idp.example",
            CRED_SUBJECT: "subject-a",
        },
    )
    assert result is credential
    assert credential.data[CRED_SUBJECT] == "subject-a"
    assert not credential.is_new


@pytest.mark.asyncio
async def test_username_cannot_be_rebound_to_new_subject() -> None:
    """Username reuse at the IdP must not take over a linked HA account."""
    credential = SimpleNamespace(
        data={
            "username": "user@example.com",
            CRED_ISSUER: "https://idp.example",
            CRED_SUBJECT: "subject-a",
        },
        is_new=False,
    )
    provider = SimpleNamespace(
        async_credentials=AsyncMock(return_value=[credential]),
        async_create_credentials=AsyncMock(),
    )
    with pytest.raises(OpenIDIdentityConflictError, match="another OIDC identity"):
        await OpenIDAuthProvider.async_get_or_create_credentials(
            provider,
            {
                "username": "user@example.com",
                CRED_ISSUER: "https://idp.example",
                CRED_SUBJECT: "subject-b",
            },
        )
    assert credential.data[CRED_SUBJECT] == "subject-a"
