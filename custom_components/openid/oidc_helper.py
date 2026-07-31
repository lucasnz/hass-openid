"""OpenID Connect ID token validation helpers."""

from __future__ import annotations

from functools import partial
from http import HTTPStatus
import secrets
from typing import Any

from aiohttp import ClientTimeout
import jwt

from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client

from .const import DEFAULT_VALIDATE_TLS


async def async_validate_id_token(
    hass: HomeAssistant,
    *,
    id_token: str,
    issuer: str,
    jwks_url: str,
    client_id: str,
    nonce: str,
    algorithms: list[str],
    validate_tls: bool = DEFAULT_VALIDATE_TLS,
) -> dict[str, Any]:
    """Validate an OIDC ID token and return its claims."""
    header = jwt.get_unverified_header(id_token)
    algorithm = header.get("alg")
    key_id = header.get("kid")

    allowed_algorithms = [
        candidate
        for candidate in algorithms
        if candidate != "none" and not candidate.startswith("HS")
    ]
    if not algorithm or algorithm not in allowed_algorithms:
        raise ValueError("ID token uses an unsupported signing algorithm")

    session = aiohttp_client.async_get_clientsession(hass, verify_ssl=validate_tls)
    async with session.get(jwks_url, timeout=ClientTimeout(total=15)) as response:
        if response.status != HTTPStatus.OK:
            raise RuntimeError(f"JWKS endpoint returned HTTP {response.status}")
        jwks_data = await response.json()

    keys = jwks_data.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("JWKS endpoint did not return signing keys")

    candidates = [
        key
        for key in keys
        if isinstance(key, dict)
        and (not key_id or key.get("kid") == key_id)
        and key.get("use", "sig") == "sig"
        and key.get("alg", algorithm) == algorithm
    ]
    if len(candidates) != 1:
        raise ValueError("Unable to select exactly one ID token signing key")

    signing_key = jwt.PyJWK.from_dict(candidates[0]).key
    decode = partial(
        jwt.decode,
        id_token,
        signing_key,
        algorithms=[algorithm],
        audience=client_id,
        issuer=issuer,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )
    claims: dict[str, Any] = await hass.async_add_executor_job(decode)

    token_nonce = claims.get("nonce")
    if not isinstance(token_nonce, str) or not secrets.compare_digest(
        token_nonce, nonce
    ):
        raise ValueError("ID token nonce does not match the authorization request")

    audience = claims.get("aud")
    if isinstance(audience, list) and len(audience) > 1:
        if claims.get("azp") != client_id:
            raise ValueError("ID token azp is invalid for a multi-audience token")

    return claims
