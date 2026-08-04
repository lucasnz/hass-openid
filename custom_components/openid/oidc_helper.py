"""OpenID Connect ID-token validation helpers."""

from __future__ import annotations

from functools import partial
import re
import secrets
from time import monotonic
from typing import Any

from aiohttp import ClientError
import jwt

from homeassistant.core import HomeAssistant

from .const import DEFAULT_VALIDATE_TLS, DOMAIN
from .network import (
    MAX_JWKS_BYTES,
    ProviderResponseError,
    async_request_json_object,
)

_JWKS_CACHE_KEY = "jwks_cache"
_JWKS_CACHE_TTL = 60 * 60
_JWKS_CACHE_MAX_TTL = 6 * 60 * 60
_JWKS_STALE_TTL = 24 * 60 * 60
_CLOCK_SKEW_SECONDS = 60


def _jwks_cache_ttl(headers: dict[str, str]) -> float | None:
    """Return a bounded JWKS freshness lifetime from HTTP cache headers."""
    cache_control = headers.get("cache-control", "")
    directives = {
        directive.strip().casefold()
        for directive in cache_control.split(",")
        if directive.strip()
    }
    if "no-store" in directives:
        return None
    if "no-cache" in directives:
        return 0

    match = re.search(r"(?:^|,)\s*max-age=(\d+)", cache_control, re.I)
    if not match:
        return _JWKS_CACHE_TTL
    try:
        max_age = min(int(match.group(1)), _JWKS_CACHE_MAX_TTL)
    except ValueError:
        return _JWKS_CACHE_TTL
    try:
        age = max(0, int(headers.get("age", "0")))
    except ValueError:
        age = 0
    return max(0, max_age - age)


async def _async_fetch_jwks(
    hass: HomeAssistant,
    *,
    issuer: str,
    jwks_url: str,
    validate_tls: bool,
    ca_cert_path: str | None = None,
    force_refresh: bool = False,
) -> dict[str, Any]:
    """Return cached JWKS, refreshing it when required."""
    cache: dict[tuple[str, str, bool, str], dict[str, Any]] = hass.data.setdefault(
        DOMAIN, {}
    ).setdefault(_JWKS_CACHE_KEY, {})
    cache_key = (issuer, jwks_url, validate_tls, ca_cert_path or "")
    cached = cache.get(cache_key)
    now = monotonic()
    if (
        not force_refresh
        and cached
        and now < cached.get("expires_at", 0.0)
    ):
        return cached["value"]

    response_headers: dict[str, str] = {}
    try:
        jwks_data = await async_request_json_object(
            hass,
            "GET",
            jwks_url,
            validate_tls=validate_tls,
            endpoint_name="JWKS endpoint",
            max_bytes=MAX_JWKS_BYTES,
            ca_cert_path=ca_cert_path,
            response_headers=response_headers,
        )
    except (ClientError, TimeoutError, ProviderResponseError):
        if cached and now < cached.get("stale_until", 0.0):
            return cached["value"]
        raise

    keys = jwks_data.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("JWKS endpoint did not return signing keys")
    cache_ttl = _jwks_cache_ttl(response_headers)
    if cache_ttl is None:
        cache.pop(cache_key, None)
    else:
        cache[cache_key] = {
            "expires_at": now + cache_ttl,
            "stale_until": now + max(cache_ttl, _JWKS_STALE_TTL),
            "value": jwks_data,
        }
    return jwks_data


def _select_signing_key(
    jwks_data: dict[str, Any],
    *,
    key_id: str | None,
    algorithm: str,
) -> Any:
    """Select exactly one usable verification key."""
    keys = jwks_data.get("keys")
    candidates = [
        key
        for key in keys
        if isinstance(key, dict)
        and (not key_id or key.get("kid") == key_id)
        and key.get("use", "sig") == "sig"
        and key.get("alg", algorithm) == algorithm
        and (
            "key_ops" not in key
            or (
                isinstance(key.get("key_ops"), list)
                and "verify" in key["key_ops"]
            )
        )
    ]
    if len(candidates) != 1:
        raise LookupError("Unable to select exactly one ID-token signing key")
    return jwt.PyJWK.from_dict(candidates[0]).key


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
    ca_cert_path: str | None = None,
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
    if not isinstance(algorithm, str) or algorithm not in allowed_algorithms:
        raise ValueError("ID token uses an unsupported signing algorithm")
    if key_id is not None and not isinstance(key_id, str):
        raise ValueError("ID token key identifier is invalid")

    jwks_data = await _async_fetch_jwks(
        hass,
        issuer=issuer,
        jwks_url=jwks_url,
        validate_tls=validate_tls,
        ca_cert_path=ca_cert_path,
    )
    try:
        signing_key = _select_signing_key(
            jwks_data,
            key_id=key_id,
            algorithm=algorithm,
        )
    except LookupError:
        # Providers rotate signing keys. Refresh once for an unknown kid before
        # treating the token as invalid.
        jwks_data = await _async_fetch_jwks(
            hass,
            issuer=issuer,
            jwks_url=jwks_url,
            validate_tls=validate_tls,
            ca_cert_path=ca_cert_path,
            force_refresh=True,
        )
        signing_key = _select_signing_key(
            jwks_data,
            key_id=key_id,
            algorithm=algorithm,
        )

    decode = partial(
        jwt.decode,
        id_token,
        signing_key,
        algorithms=[algorithm],
        audience=client_id,
        issuer=issuer,
        leeway=_CLOCK_SKEW_SECONDS,
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


async def async_validate_logout_token(
    hass: HomeAssistant,
    *,
    logout_token: str,
    issuer: str,
    jwks_url: str,
    client_id: str,
    algorithms: list[str],
    validate_tls: bool = DEFAULT_VALIDATE_TLS,
    ca_cert_path: str | None = None,
) -> dict[str, Any]:
    """Validate an OIDC back-channel logout token."""
    header = jwt.get_unverified_header(logout_token)
    algorithm = header.get("alg")
    key_id = header.get("kid")
    token_type = header.get("typ")
    if token_type is not None and (
        not isinstance(token_type, str)
        or token_type.casefold() != "logout+jwt"
    ):
        raise ValueError("Logout token type is invalid")
    allowed_algorithms = [
        candidate
        for candidate in algorithms
        if candidate != "none" and not candidate.startswith("HS")
    ]
    if not isinstance(algorithm, str) or algorithm not in allowed_algorithms:
        raise ValueError("Logout token uses an unsupported signing algorithm")

    jwks_data = await _async_fetch_jwks(
        hass,
        issuer=issuer,
        jwks_url=jwks_url,
        validate_tls=validate_tls,
        ca_cert_path=ca_cert_path,
    )
    try:
        signing_key = _select_signing_key(
            jwks_data, key_id=key_id, algorithm=algorithm
        )
    except LookupError:
        jwks_data = await _async_fetch_jwks(
            hass,
            issuer=issuer,
            jwks_url=jwks_url,
            validate_tls=validate_tls,
            ca_cert_path=ca_cert_path,
            force_refresh=True,
        )
        signing_key = _select_signing_key(
            jwks_data, key_id=key_id, algorithm=algorithm
        )

    decode = partial(
        jwt.decode,
        logout_token,
        signing_key,
        algorithms=[algorithm],
        audience=client_id,
        issuer=issuer,
        leeway=_CLOCK_SKEW_SECONDS,
        options={"require": ["iat", "iss", "aud", "jti", "events"]},
    )
    claims: dict[str, Any] = await hass.async_add_executor_job(decode)
    if "nonce" in claims:
        raise ValueError("Logout token must not contain a nonce")
    events = claims.get("events")
    event_name = "http://schemas.openid.net/event/backchannel-logout"
    if (
        not isinstance(events, dict)
        or not isinstance(events.get(event_name), dict)
    ):
        raise ValueError("Logout token is missing the back-channel logout event")
    if not isinstance(claims.get("sub"), str) and not isinstance(
        claims.get("sid"), str
    ):
        raise ValueError("Logout token must contain sub or sid")
    return claims
