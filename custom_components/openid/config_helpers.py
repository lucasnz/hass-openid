"""Config helpers for the OpenID integration."""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network, ip_network
import logging
from typing import Any

from homeassistant.core import HomeAssistant

from .const import (
    CONF_AUTHORIZE_URL,
    CONF_ID_TOKEN_SIGNING_ALGORITHMS,
    CONF_ISSUER,
    CONF_JWKS_URL,
    CONF_LOGOUT_URL,
    CONF_TOKEN_URL,
    CONF_TRUSTED_IPS,
    CONF_USER_INFO_URL,
    CONF_VALIDATE_TLS,
    DATA_ACTIVE_CONFIG,
    DEFAULT_VALIDATE_TLS,
    DISCOVERY_PKCE_AVAILABLE,
    DOMAIN,
)
from .network import (
    MAX_DISCOVERY_BYTES,
    async_request_json_object,
    validate_provider_url,
)

_LOGGER = logging.getLogger(__name__)

type TrustedNetwork = IPv4Network | IPv6Network


def get_domain_data(hass: HomeAssistant) -> dict[str, Any]:
    """Return the integration data store."""
    return hass.data.setdefault(DOMAIN, {})


def get_active_config(hass: HomeAssistant) -> dict[str, Any] | None:
    """Return the active runtime configuration."""
    return get_domain_data(hass).get(DATA_ACTIVE_CONFIG)


def set_active_config(
    hass: HomeAssistant, raw_config: dict[str, Any] | None
) -> dict[str, Any] | None:
    """Set the active runtime configuration."""
    store = get_domain_data(hass)
    if raw_config is None:
        store.pop(DATA_ACTIVE_CONFIG, None)
        return None

    runtime_config = build_runtime_config(raw_config)
    store[DATA_ACTIVE_CONFIG] = runtime_config
    return runtime_config


def build_runtime_config(raw_config: dict[str, Any]) -> dict[str, Any]:
    """Normalize stored config for runtime use."""
    runtime_config = dict(raw_config)
    runtime_config.setdefault(CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS)

    trusted_networks: list[TrustedNetwork] = []
    trusted_ip_entries = runtime_config.get(CONF_TRUSTED_IPS, [])
    if isinstance(trusted_ip_entries, str):
        trusted_ip_entries = [trusted_ip_entries]

    for entry in trusted_ip_entries:
        try:
            network = ip_network(entry, strict=False)
        except ValueError:
            _LOGGER.warning("Invalid trusted IP/network '%s'; ignoring", entry)
            continue
        trusted_networks.append(network)

    runtime_config[CONF_TRUSTED_IPS] = trusted_networks
    return runtime_config


def validate_runtime_provider_urls(config: dict[str, Any]) -> None:
    """Validate every configured provider endpoint before activating it."""
    for key in (
        CONF_AUTHORIZE_URL,
        CONF_TOKEN_URL,
        CONF_USER_INFO_URL,
        CONF_JWKS_URL,
        CONF_LOGOUT_URL,
    ):
        if value := config.get(key):
            config[key] = validate_provider_url(value, field=key)

    if issuer := config.get(CONF_ISSUER):
        config[CONF_ISSUER] = validate_provider_url(issuer, field=CONF_ISSUER).rstrip(
            "/"
        )


async def async_discover_configuration(
    hass: HomeAssistant,
    configure_url: str,
    validate_tls: bool = DEFAULT_VALIDATE_TLS,
    expected_issuer: str | None = None,
) -> dict[str, Any]:
    """Fetch and strictly validate an OpenID discovery document."""
    configure_url = validate_provider_url(
        configure_url, field="OpenID discovery URL"
    )
    _LOGGER.debug("Fetching OpenID discovery metadata")
    config_data = await async_request_json_object(
        hass,
        "GET",
        configure_url,
        validate_tls=validate_tls,
        endpoint_name="OpenID discovery endpoint",
        max_bytes=MAX_DISCOVERY_BYTES,
    )

    issuer = config_data.get("issuer")
    if not isinstance(issuer, str):
        raise ValueError("OpenID discovery metadata is missing a string issuer")
    issuer = validate_provider_url(issuer, field="issuer").rstrip("/")
    if expected_issuer and issuer != expected_issuer.rstrip("/"):
        raise ValueError("OpenID discovery issuer changed unexpectedly")

    endpoint_mapping = {
        CONF_AUTHORIZE_URL: "authorization_endpoint",
        CONF_TOKEN_URL: "token_endpoint",
        CONF_USER_INFO_URL: "userinfo_endpoint",
        CONF_JWKS_URL: "jwks_uri",
        CONF_LOGOUT_URL: "end_session_endpoint",
    }
    result: dict[str, Any] = {CONF_ISSUER: issuer}
    for target, source in endpoint_mapping.items():
        value = config_data.get(source)
        if value is None and target == CONF_LOGOUT_URL:
            continue
        if not isinstance(value, str):
            raise ValueError(f"OpenID discovery metadata is missing {source}")
        result[target] = validate_provider_url(value, field=source)

    algorithms = config_data.get(
        "id_token_signing_alg_values_supported", ["RS256"]
    )
    if (
        not isinstance(algorithms, list)
        or not algorithms
        or not all(isinstance(value, str) and value for value in algorithms)
    ):
        raise ValueError("Invalid ID token signing algorithm metadata")
    result[CONF_ID_TOKEN_SIGNING_ALGORITHMS] = algorithms

    pkce_methods = config_data.get("code_challenge_methods_supported", [])
    if not isinstance(pkce_methods, list):
        raise ValueError("Invalid PKCE discovery metadata")
    result[DISCOVERY_PKCE_AVAILABLE] = "S256" in pkce_methods
    return result
