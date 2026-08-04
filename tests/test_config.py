"""Tests for OpenID configuration and config flow behavior."""

from typing import cast

import pytest
import voluptuous as vol

from homeassistant.core import HomeAssistant

from custom_components.openid import _async_prepare_config
from custom_components.openid.config_flow import (
    CONF_ID_TOKEN_SIGNING_ALGORITHMS_INPUT,
    CONF_TRUSTED_IPS_INPUT,
    OpenIDConfigFlow,
)
from custom_components.openid.const import (
    CONF_ALLOW_LEGACY_OAUTH,
    CONF_AUTHORIZE_URL,
    CONF_BLOCK_LOGIN,
    CONF_CA_CERT_PATH,
    CONF_CONFIGURE_URL,
    CONF_CREATE_USER,
    CONF_ERROR_URL,
    CONF_ID_TOKEN_SIGNING_ALGORITHMS,
    CONF_ISSUER,
    CONF_JWKS_URL,
    CONF_LOGOUT_URL,
    CONF_OPENID_TEXT,
    CONF_POST_LOGOUT_URL,
    CONF_SCOPE,
    CONF_TOKEN_URL,
    CONF_USER_INFO_URL,
    CONF_USE_HEADER_AUTH,
    CONF_USE_PKCE,
    CONF_VALIDATE_TLS,
)


@pytest.mark.asyncio
async def test_manual_oidc_requires_issuer_and_jwks() -> None:
    """Manual OpenID configuration must provide validation metadata."""
    with pytest.raises(RuntimeError, match="issuer, jwks_url"):
        await _async_prepare_config(
            cast(HomeAssistant, object()),
            {
                CONF_AUTHORIZE_URL: "https://idp.example/authorize",
                CONF_TOKEN_URL: "https://idp.example/token",
                CONF_USER_INFO_URL: "https://idp.example/userinfo",
                CONF_SCOPE: "openid profile email",
            },
        )


@pytest.mark.asyncio
async def test_manual_oidc_defaults_to_rs256() -> None:
    """Manual OpenID configuration gets a conservative algorithm default."""
    prepared = await _async_prepare_config(
        cast(HomeAssistant, object()),
        {
            CONF_AUTHORIZE_URL: "https://idp.example/authorize",
            CONF_TOKEN_URL: "https://idp.example/token",
            CONF_USER_INFO_URL: "https://idp.example/userinfo",
            CONF_SCOPE: "openid profile email",
            CONF_ISSUER: "https://idp.example",
            CONF_JWKS_URL: "https://idp.example/jwks",
        },
    )

    assert prepared[CONF_ID_TOKEN_SIGNING_ALGORITHMS] == ["RS256"]


@pytest.mark.asyncio
async def test_manual_oauth_without_openid_does_not_require_oidc_metadata() -> None:
    """OAuth plus UserInfo remains available without issuer or JWKS metadata."""
    prepared = await _async_prepare_config(
        cast(HomeAssistant, object()),
        {
            CONF_AUTHORIZE_URL: "https://idp.example/authorize",
            CONF_TOKEN_URL: "https://idp.example/token",
            CONF_USER_INFO_URL: "https://idp.example/userinfo",
            CONF_SCOPE: "profile email",
            CONF_ALLOW_LEGACY_OAUTH: True,
        },
    )

    assert CONF_ISSUER not in prepared
    assert CONF_JWKS_URL not in prepared


@pytest.mark.asyncio
async def test_oauth_userinfo_mode_requires_explicit_opt_in() -> None:
    """Removing openid scope cannot silently downgrade identity validation."""
    with pytest.raises(RuntimeError, match="explicitly enabled"):
        await _async_prepare_config(
            cast(HomeAssistant, object()),
            {
                CONF_AUTHORIZE_URL: "https://idp.example/authorize",
                CONF_TOKEN_URL: "https://idp.example/token",
                CONF_USER_INFO_URL: "https://idp.example/userinfo",
                CONF_SCOPE: "profile email",
            },
        )


@pytest.mark.asyncio
async def test_manual_provider_form_requires_oidc_metadata(
    hass: HomeAssistant,
) -> None:
    """The manual config flow reports missing OIDC metadata before saving."""
    flow = OpenIDConfigFlow()
    flow.hass = hass
    flow._manual_mode = True
    flow._config_data = {CONF_SCOPE: "openid profile email"}

    result = await flow.async_step_provider(
        {
            CONF_AUTHORIZE_URL: "https://idp.example/authorize",
            CONF_TOKEN_URL: "https://idp.example/token",
            CONF_USER_INFO_URL: "https://idp.example/userinfo",
            CONF_LOGOUT_URL: "",
            CONF_VALIDATE_TLS: True,
            CONF_USE_PKCE: True,
            CONF_ISSUER: "",
            CONF_JWKS_URL: "",
            CONF_ID_TOKEN_SIGNING_ALGORITHMS_INPUT: "RS256",
        }
    )

    assert result["type"] == "form"
    assert result["step_id"] == "provider"
    assert result["errors"]["base"] == "missing_oidc_metadata"


@pytest.mark.asyncio
async def test_logout_endpoint_is_optional_in_provider_form(
    hass: HomeAssistant,
) -> None:
    """The logout endpoint remains optional in discovery mode."""
    flow = OpenIDConfigFlow()
    flow.hass = hass
    flow._config_data = {
        CONF_AUTHORIZE_URL: "https://idp.example/authorize",
        CONF_TOKEN_URL: "https://idp.example/token",
        CONF_USER_INFO_URL: "https://idp.example/userinfo",
    }

    result = await flow.async_step_provider()
    markers = [
        marker
        for marker in result["data_schema"].schema
        if getattr(marker, "schema", None) == CONF_LOGOUT_URL
    ]

    assert len(markers) == 1
    assert isinstance(markers[0], vol.Optional)


@pytest.mark.asyncio
async def test_switching_from_discovery_to_manual_clears_oidc_metadata(
    hass: HomeAssistant,
) -> None:
    """Discovered validation metadata is not silently reused in manual mode."""
    flow = OpenIDConfigFlow()
    flow.hass = hass
    flow._config_data = {
        CONF_CONFIGURE_URL: "https://idp.example/.well-known/openid-configuration",
        CONF_SCOPE: "openid profile email",
        CONF_ISSUER: "https://old-idp.example",
        CONF_JWKS_URL: "https://old-idp.example/jwks",
        CONF_ID_TOKEN_SIGNING_ALGORITHMS: ["RS256"],
    }

    result = await flow.async_step_manual()

    assert result["step_id"] == "identity"
    assert CONF_CONFIGURE_URL not in flow._config_data
    assert CONF_ISSUER not in flow._config_data
    assert CONF_JWKS_URL not in flow._config_data
    assert CONF_ID_TOKEN_SIGNING_ALGORITHMS not in flow._config_data


@pytest.mark.asyncio
async def test_provider_form_rejects_ca_with_disabled_tls(
    hass: HomeAssistant,
) -> None:
    """A private CA is not accepted when certificate validation is disabled."""
    flow = OpenIDConfigFlow()
    flow.hass = hass
    flow._manual_mode = True
    flow._config_data = {CONF_SCOPE: "openid profile email"}

    result = await flow.async_step_provider(
        {
            CONF_AUTHORIZE_URL: "https://idp.example/authorize",
            CONF_TOKEN_URL: "https://idp.example/token",
            CONF_USER_INFO_URL: "https://idp.example/userinfo",
            CONF_LOGOUT_URL: "",
            CONF_VALIDATE_TLS: False,
            CONF_CA_CERT_PATH: "certs/private-ca.pem",
            CONF_USE_PKCE: True,
            CONF_ISSUER: "https://idp.example",
            CONF_JWKS_URL: "https://idp.example/jwks",
            CONF_ID_TOKEN_SIGNING_ALGORITHMS_INPUT: "RS256",
        }
    )

    assert result["type"] == "form"
    assert result["errors"]["base"] == "invalid_tls_configuration"


@pytest.mark.asyncio
async def test_advanced_flow_requires_explicit_legacy_oauth_opt_in(
    hass: HomeAssistant,
) -> None:
    """The config flow blocks an accidental downgrade from OIDC."""
    flow = OpenIDConfigFlow()
    flow.hass = hass
    flow._config_data = {CONF_SCOPE: "profile email"}
    flow.context = {"source": "user"}

    result = await flow.async_step_advanced(
        {
            CONF_ALLOW_LEGACY_OAUTH: False,
            CONF_BLOCK_LOGIN: False,
            CONF_TRUSTED_IPS_INPUT: "",
            CONF_OPENID_TEXT: "OpenID",
            CONF_CREATE_USER: False,
            CONF_USE_HEADER_AUTH: True,
            CONF_ERROR_URL: "",
            CONF_POST_LOGOUT_URL: "",
        }
    )

    assert result["type"] == "form"
    assert result["errors"][CONF_ALLOW_LEGACY_OAUTH] == "legacy_oauth_required"


@pytest.mark.asyncio
async def test_manual_provider_form_rejects_insecure_remote_endpoint(
    hass: HomeAssistant,
) -> None:
    """Unsafe provider URLs are rejected before an entry is created."""
    flow = OpenIDConfigFlow()
    flow.hass = hass
    flow._manual_mode = True
    flow._config_data = {CONF_SCOPE: "openid profile email"}

    result = await flow.async_step_provider(
        {
            CONF_AUTHORIZE_URL: "http://idp.example/authorize",
            CONF_TOKEN_URL: "https://idp.example/token",
            CONF_USER_INFO_URL: "https://idp.example/userinfo",
            CONF_LOGOUT_URL: "",
            CONF_VALIDATE_TLS: True,
            CONF_CA_CERT_PATH: "",
            CONF_USE_PKCE: True,
            CONF_ISSUER: "https://idp.example",
            CONF_JWKS_URL: "https://idp.example/jwks",
            CONF_ID_TOKEN_SIGNING_ALGORITHMS_INPUT: "RS256",
        }
    )

    assert result["type"] == "form"
    assert result["errors"]["base"] == "invalid_provider_configuration"
