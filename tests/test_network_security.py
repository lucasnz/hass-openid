"""Tests for provider URL and OAuth request hardening."""

from base64 import b64decode
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from custom_components.openid import oauth_helper, oidc_helper
from custom_components.openid.network import (
    async_get_ssl_parameter,
    validate_issuer_url,
    validate_provider_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://idp.example/token",
        "https://user:pass@idp.example/token",
        "javascript:alert(1)",
    ],
)
def test_provider_url_rejects_unsafe_values(url: str) -> None:
    """Remote provider endpoints must be absolute HTTPS URLs."""
    with pytest.raises(ValueError):
        validate_provider_url(url)


def test_loopback_http_is_allowed_for_development() -> None:
    """Explicit loopback development providers may use HTTP."""
    assert validate_provider_url("http://127.0.0.1:8080/token")


@pytest.mark.asyncio
async def test_basic_auth_form_encodes_client_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RFC 6749 form encoding occurs before Basic Base64 encoding."""
    request_json = AsyncMock(return_value={"access_token": "token"})
    monkeypatch.setattr(oauth_helper, "async_request_json_object", request_json)
    await oauth_helper.exchange_code_for_token(
        SimpleNamespace(),
        token_url="https://idp.example/token",
        code="code",
        client_id="client:id",
        client_secret="secret value",
        redirect_uri="https://ha.example/callback",
        validate_tls=True,
    )
    headers = request_json.await_args.kwargs["headers"]
    encoded = headers["Authorization"].split(" ", 1)[1]
    assert b64decode(encoded).decode() == "client%3Aid:secret+value"


@pytest.mark.asyncio
async def test_custom_ca_must_remain_inside_config_directory(tmp_path) -> None:
    """A configured CA path cannot read arbitrary host files."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    outside = tmp_path / "outside.pem"
    outside.write_text("not-a-certificate")
    hass = SimpleNamespace(
        config=SimpleNamespace(config_dir=str(config_dir)),
        data={},
        async_add_executor_job=AsyncMock(
            side_effect=lambda target, *args: target(*args)
        ),
    )
    with pytest.raises(ValueError, match="inside the Home Assistant config"):
        await async_get_ssl_parameter(
            hass,
            validate_tls=True,
            ca_cert_path=str(outside),
        )


@pytest.mark.asyncio
async def test_custom_ca_requires_tls_validation() -> None:
    """Custom trust material and disabled verification are contradictory."""
    hass = SimpleNamespace()
    with pytest.raises(ValueError, match="TLS validation is disabled"):
        await async_get_ssl_parameter(
            hass,
            validate_tls=False,
            ca_cert_path="certs/private-ca.pem",
        )


def test_issuer_preserves_significant_trailing_slash() -> None:
    """OIDC issuer identifiers are compared exactly, including a slash."""
    assert validate_issuer_url("https://idp.example/") == "https://idp.example/"


def test_jwks_no_cache_requires_revalidation() -> None:
    """A provider no-cache directive prevents fresh-cache reuse."""
    assert oidc_helper._jwks_cache_ttl({"cache-control": "no-cache"}) == 0
