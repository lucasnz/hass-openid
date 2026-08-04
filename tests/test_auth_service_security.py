"""Security tests for provider identity claim validation."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET

from custom_components.openid import auth_service
from custom_components.openid.auth_service import (
    ProviderAuthenticationError,
    async_exchange_and_validate_identity,
)
from custom_components.openid.const import (
    CONF_SCOPE,
    CONF_TOKEN_URL,
    CONF_USE_HEADER_AUTH,
    CONF_USER_INFO_URL,
    CONF_USERNAME_FIELD,
    CONF_VALIDATE_TLS,
)


def _legacy_oauth_config() -> dict[str, object]:
    return {
        CONF_CLIENT_ID: "client-id",
        CONF_CLIENT_SECRET: "client-secret",
        CONF_TOKEN_URL: "https://idp.example/token",
        CONF_USER_INFO_URL: "https://idp.example/userinfo",
        CONF_SCOPE: "profile email",
        CONF_USERNAME_FIELD: "email",
        CONF_USE_HEADER_AUTH: True,
        CONF_VALIDATE_TLS: True,
    }


@pytest.mark.asyncio
async def test_non_string_optional_identity_claim_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed display claims cannot reach HA user or Person APIs."""
    monkeypatch.setattr(
        auth_service,
        "exchange_code_for_token",
        AsyncMock(return_value={"access_token": "access-token"}),
    )
    monkeypatch.setattr(
        auth_service,
        "fetch_user_info",
        AsyncMock(
            return_value={
                "email": "user@example.com",
                "name": ["not", "a", "string"],
            }
        ),
    )

    with pytest.raises(ProviderAuthenticationError, match="name claim"):
        await async_exchange_and_validate_identity(
            SimpleNamespace(),
            config=_legacy_oauth_config(),
            code="provider-code",
            redirect_uri="https://ha.example/auth/openid/callback",
            nonce=None,
            code_verifier=None,
        )


@pytest.mark.asyncio
async def test_malformed_email_verified_claim_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present email_verified claim must be the boolean true."""
    monkeypatch.setattr(
        auth_service,
        "exchange_code_for_token",
        AsyncMock(return_value={"access_token": "access-token"}),
    )
    monkeypatch.setattr(
        auth_service,
        "fetch_user_info",
        AsyncMock(
            return_value={
                "email": "user@example.com",
                "email_verified": "true",
            }
        ),
    )

    with pytest.raises(ProviderAuthenticationError, match="verified"):
        await async_exchange_and_validate_identity(
            SimpleNamespace(),
            config=_legacy_oauth_config(),
            code="provider-code",
            redirect_uri="https://ha.example/auth/openid/callback",
            nonce=None,
            code_verifier=None,
        )
