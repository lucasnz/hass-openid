"""OpenID / OAuth2 login component for Home Assistant."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from functools import wraps
import logging
from pathlib import Path
from typing import Any

import hass_frontend
from aiohttp import ClientError
import voluptuous as vol

from homeassistant.auth import InvalidAuthError, InvalidProvider
from homeassistant.auth.models import Credentials
from homeassistant.components.frontend import add_extra_js_url
from homeassistant.components.http import StaticPathConfig
from homeassistant.config_entries import SOURCE_IMPORT, ConfigEntry
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryError, ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.typing import ConfigType

from . import views as openid_views
from .auth_provider import async_register_auth_provider
from .config_helpers import (
    async_discover_configuration,
    async_validate_tls_configuration,
    set_active_config,
    validate_runtime_provider_urls,
)
from .const import (
    CONF_ALLOW_LEGACY_OAUTH,
    CONF_AUTHORIZE_URL,
    CONF_BLOCK_LOGIN,
    CONF_CA_CERT_PATH,
    CONF_POST_LOGOUT_URL,
    CONF_CONFIGURE_URL,
    CONF_CREATE_USER,
    CONF_ERROR_URL,
    CONF_ID_TOKEN_SIGNING_ALGORITHMS,
    CONF_ISSUER,
    CONF_JWKS_URL,
    CONF_LOGOUT_URL,
    CONF_OPENID_TEXT,
    CONF_SCOPE,
    CONF_TOKEN_URL,
    CONF_TRUSTED_IPS,
    CONF_USE_HEADER_AUTH,
    CONF_USE_PKCE,
    CONF_USER_INFO_URL,
    CONF_USERNAME_FIELD,
    CONF_VALIDATE_TLS,
    CRED_ID_TOKEN,
    CRED_LOGOUT_REDIRECT_URI,
    CRED_SESSION_STATE,
    DATA_ACTIVE_CONFIG,
    DATA_ACTIVE_ENTRY_ID,
    DATA_AUTH_PROVIDER,
    DATA_SHARED_INITIALIZED,
    DATA_YAML_IMPORT_CONFIG,
    DEFAULT_SCOPE,
    DEFAULT_USE_HEADER_AUTH,
    DEFAULT_USERNAME_FIELD,
    DEFAULT_VALIDATE_TLS,
    DISCOVERY_PKCE_AVAILABLE,
    DOMAIN,
)
from .http_helper import override_authorize_login_flow, override_authorize_route
from .network import ProviderResponseError

_LOGGER = logging.getLogger(__name__)

_DISCOVERY_REFRESH_INTERVAL = timedelta(hours=6)

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required(CONF_CLIENT_ID): cv.string,
                vol.Required(CONF_CLIENT_SECRET): cv.string,
                vol.Optional(CONF_ALLOW_LEGACY_OAUTH, default=False): cv.boolean,
                vol.Optional(CONF_AUTHORIZE_URL): cv.url,
                vol.Optional(CONF_TOKEN_URL): cv.url,
                vol.Optional(CONF_USER_INFO_URL): cv.url,
                vol.Optional(CONF_CONFIGURE_URL): cv.url,
                vol.Optional(CONF_ISSUER): cv.url,
                vol.Optional(CONF_JWKS_URL): cv.url,
                vol.Optional(CONF_ID_TOKEN_SIGNING_ALGORITHMS): vol.All(
                    cv.ensure_list, [cv.string]
                ),
                vol.Optional(CONF_SCOPE, default=DEFAULT_SCOPE): cv.string,
                vol.Optional(
                    CONF_USERNAME_FIELD, default=DEFAULT_USERNAME_FIELD
                ): cv.string,
                vol.Optional(CONF_CREATE_USER, default=False): cv.boolean,
                vol.Optional(CONF_BLOCK_LOGIN, default=False): cv.boolean,
                vol.Optional(CONF_ERROR_URL): cv.url,
                vol.Optional(CONF_VALIDATE_TLS, default=DEFAULT_VALIDATE_TLS): cv.boolean,
                vol.Optional(CONF_CA_CERT_PATH): cv.string,
                vol.Optional(
                    CONF_USE_HEADER_AUTH, default=DEFAULT_USE_HEADER_AUTH
                ): cv.boolean,
                vol.Optional(CONF_USE_PKCE): cv.boolean,
                vol.Optional(CONF_POST_LOGOUT_URL): cv.url,
                vol.Optional(
                    CONF_OPENID_TEXT, default="OpenID / OAuth2 Authentication"
                ): cv.string,
                vol.Optional(CONF_TRUSTED_IPS, default=[]): vol.All(
                    cv.ensure_list, [cv.string]
                ),
                vol.Optional(CONF_LOGOUT_URL): cv.url,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the OpenID component."""
    await _async_setup_shared(hass)

    yaml_config = config.get(DOMAIN)
    if yaml_config:
        try:
            prepared_yaml_config = await _async_prepare_config(hass, dict(yaml_config))
            hass.data[DOMAIN][DATA_YAML_IMPORT_CONFIG] = prepared_yaml_config
            set_active_config(
                hass,
                prepared_yaml_config,
            )
            _activate_runtime_patches(hass)
        except Exception as err:  # noqa: BLE001
            set_active_config(hass, None)
            _restore_runtime_patches(hass)
            _LOGGER.error("Failed to prepare YAML OpenID configuration: %s", err)
            return False

        hass.async_create_task(
            hass.config_entries.flow.async_init(
                DOMAIN,
                context={"source": SOURCE_IMPORT},
                data=prepared_yaml_config,
            )
        )

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up OpenID from a config entry."""
    await _async_setup_shared(hass)
    runtime_config = dict(entry.data)
    if yaml_config := hass.data[DOMAIN].get(DATA_YAML_IMPORT_CONFIG):
        runtime_config = dict(yaml_config)
    else:
        try:
            runtime_config = await _async_prepare_config(hass, runtime_config)
        except (ClientError, TimeoutError) as err:
            raise ConfigEntryNotReady(
                "OpenID provider discovery is not currently available"
            ) from err
        except ProviderResponseError as err:
            if err.transient:
                raise ConfigEntryNotReady(
                    "OpenID provider discovery is temporarily unavailable"
                ) from err
            raise ConfigEntryError(
                "OpenID provider discovery returned an invalid response"
            ) from err
        except (RuntimeError, ValueError) as err:
            raise ConfigEntryError(str(err)) from err
    set_active_config(hass, runtime_config)
    try:
        _activate_runtime_patches(hass)
    except Exception as err:  # noqa: BLE001
        set_active_config(hass, None)
        raise ConfigEntryError(
            "OpenID is incompatible with the current Home Assistant "
            "authentication routes"
        ) from err
    hass.data[DOMAIN][DATA_ACTIVE_ENTRY_ID] = entry.entry_id

    if CONF_CONFIGURE_URL in entry.data and not yaml_config:
        async def _async_refresh_discovery(_now: Any) -> None:
            """Refresh discovery metadata without interrupting active sessions."""
            domain_data = hass.data.get(DOMAIN, {})
            if domain_data.get(DATA_ACTIVE_ENTRY_ID) != entry.entry_id:
                return
            try:
                refreshed = await _async_prepare_config(hass, dict(entry.data))
            except Exception:  # noqa: BLE001
                _LOGGER.warning(
                    "Unable to refresh OpenID discovery metadata; retaining the "
                    "last validated configuration",
                    exc_info=True,
                )
                return
            set_active_config(hass, refreshed)

        entry.async_on_unload(
            async_track_time_interval(
                hass,
                _async_refresh_discovery,
                _DISCOVERY_REFRESH_INTERVAL,
            )
        )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload an OpenID config entry."""
    domain_data = hass.data.get(DOMAIN)
    if not domain_data:
        return True

    if domain_data.get(DATA_ACTIVE_ENTRY_ID) == entry.entry_id:
        # OpenID refresh tokens must not remain usable after the integration is
        # unloaded. This also makes config-entry reloads explicit: active SSO
        # sessions are revoked and must authenticate against the new config.
        for user in await hass.auth.async_get_users():
            refresh_tokens = getattr(user, "refresh_tokens", {})
            tokens = (
                list(refresh_tokens.values())
                if isinstance(refresh_tokens, dict)
                else list(refresh_tokens)
            )
            for refresh_token in tokens:
                credential = getattr(refresh_token, "credential", None)
                if getattr(credential, "auth_provider_type", None) == DOMAIN:
                    hass.auth.async_remove_refresh_token(refresh_token)

        provider = domain_data.pop(DATA_AUTH_PROVIDER, None)
        providers = getattr(hass.auth, "_providers", None)  # noqa: SLF001
        if (
            isinstance(providers, dict)
            and providers.get((DOMAIN, None)) is provider
        ):
            providers.pop((DOMAIN, None), None)

        domain_data.pop(DATA_ACTIVE_ENTRY_ID, None)
        domain_data.pop(DATA_ACTIVE_CONFIG, None)
        _restore_runtime_patches(hass)

    return True


async def _async_prepare_config(
    hass: HomeAssistant, config: dict[str, Any]
) -> dict[str, Any]:
    """Prepare raw config for runtime use."""
    config.setdefault(CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS)
    openid_requested = "openid" in config.get(CONF_SCOPE, DEFAULT_SCOPE).split()
    if not openid_requested and not config.get(CONF_ALLOW_LEGACY_OAUTH, False):
        raise RuntimeError(
            "The openid scope is required unless legacy OAuth UserInfo mode is explicitly enabled"
        )

    if CONF_CONFIGURE_URL in config:
        # Refresh discovery metadata on every setup/reload. This detects issuer
        # changes and avoids indefinitely trusting stale endpoints.
        discovered = await async_discover_configuration(
            hass,
            config[CONF_CONFIGURE_URL],
            validate_tls=bool(
                config.get(CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS)
            ),
            expected_issuer=config.get(CONF_ISSUER),
            ca_cert_path=config.get(CONF_CA_CERT_PATH),
        )
        for key in (
            CONF_AUTHORIZE_URL,
            CONF_TOKEN_URL,
            CONF_USER_INFO_URL,
            CONF_ISSUER,
            CONF_JWKS_URL,
            CONF_ID_TOKEN_SIGNING_ALGORITHMS,
        ):
            config[key] = discovered[key]

        if discovered.get(CONF_LOGOUT_URL):
            config[CONF_LOGOUT_URL] = discovered[CONF_LOGOUT_URL]
        else:
            config.pop(CONF_LOGOUT_URL, None)
        if CONF_USE_PKCE not in config:
            config[CONF_USE_PKCE] = bool(discovered[DISCOVERY_PKCE_AVAILABLE])

    required_keys = [CONF_AUTHORIZE_URL, CONF_TOKEN_URL, CONF_USER_INFO_URL]
    if openid_requested:
        required_keys.extend((CONF_ISSUER, CONF_JWKS_URL))
        algorithms = config.setdefault(CONF_ID_TOKEN_SIGNING_ALGORITHMS, ["RS256"])
        if isinstance(algorithms, str):
            algorithms = [algorithms]
        algorithms = [
            value
            for value in algorithms
            if isinstance(value, str)
            and value
            and value != "none"
            and not value.startswith("HS")
        ]
        if not algorithms:
            raise RuntimeError(
                "At least one asymmetric ID token signing algorithm is required"
            )
        config[CONF_ID_TOKEN_SIGNING_ALGORITHMS] = algorithms

    missing = [key for key in required_keys if not config.get(key)]
    if missing:
        source = "discovery" if CONF_CONFIGURE_URL in config else "manual configuration"
        raise RuntimeError(
            f"OpenID {source} did not provide required values: {', '.join(missing)}"
        )

    validate_runtime_provider_urls(config)
    await async_validate_tls_configuration(hass, config)
    return config


def _activate_runtime_patches(hass: HomeAssistant) -> None:
    """Install runtime monkey patches atomically while config is active."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    if domain_data.get("_runtime_patches_active"):
        return

    async def _async_clear_logout_metadata(credential: Credentials) -> None:
        """Clear local logout-related metadata from credentials."""
        cleared = False
        if credential.data.pop(CRED_ID_TOKEN, None) is not None:
            cleared = True
        if credential.data.pop(CRED_SESSION_STATE, None) is not None:
            cleared = True

        if cleared:
            hass.auth.async_update_user_credentials_data(
                credential, dict(credential.data)
            )

    original_remove_refresh_token = hass.auth.async_remove_refresh_token
    original_create_access_token = hass.auth.async_create_access_token

    @wraps(original_remove_refresh_token)
    def _patched_remove_refresh_token(
        refresh_token: Any, *args: Any, **kwargs: Any
    ) -> None:
        credential = getattr(refresh_token, "credential", None)
        if (
            credential is not None
            and getattr(credential, "auth_provider_type", None) == DOMAIN
        ):
            has_logout_metadata = any(
                credential.data.get(key)
                for key in (
                    CRED_ID_TOKEN,
                    CRED_SESSION_STATE,
                    CRED_LOGOUT_REDIRECT_URI,
                )
            )
            if has_logout_metadata:
                hass.async_create_background_task(
                    _async_clear_logout_metadata(credential),
                    name="openid_clear_logout_metadata",
                )

        original_remove_refresh_token(refresh_token, *args, **kwargs)

    @wraps(original_create_access_token)
    def _patched_create_access_token(
        refresh_token: Any, *args: Any, **kwargs: Any
    ) -> str:
        """Reject and revoke tokens whose original auth provider was removed."""
        try:
            return original_create_access_token(refresh_token, *args, **kwargs)
        except InvalidProvider as err:
            credential = getattr(refresh_token, "credential", None)
            provider_type = getattr(credential, "auth_provider_type", None)
            provider_id = getattr(credential, "auth_provider_id", None)
            if provider_type != DOMAIN:
                raise
            _LOGGER.warning(
                "Removing stale refresh token for unavailable OpenID provider %s",
                provider_id,
            )
            try:
                # Bypass the OpenID logout wrapper. There is no available provider
                # to notify, and this token must be removed before the next retry.
                original_remove_refresh_token(refresh_token)
            except Exception:  # noqa: BLE001
                _LOGGER.exception(
                    "Failed to remove stale refresh token for unavailable provider"
                )

            # TokenView converts InvalidAuthError into HTTP 403. This tells the
            # client that the stored refresh token is no longer usable.
            raise InvalidAuthError(
                "Authentication provider is no longer available; sign in again"
            ) from err

    restore_callbacks: list[Any] = []
    try:
        authorize_restore = override_authorize_route(hass)
        if authorize_restore is None:
            raise RuntimeError("Unable to patch /auth/authorize")
        restore_callbacks.append(authorize_restore)

        login_flow_restore = override_authorize_login_flow(hass)
        if login_flow_restore is None:
            raise RuntimeError("Unable to patch /auth/login_flow")
        restore_callbacks.append(login_flow_restore)

        hass.auth.async_remove_refresh_token = _patched_remove_refresh_token
        hass.auth.async_create_access_token = _patched_create_access_token
    except Exception:
        for restore in reversed(restore_callbacks):
            try:
                restore()
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Failed to roll back an OpenID route patch")
        if hass.auth.async_remove_refresh_token is _patched_remove_refresh_token:
            hass.auth.async_remove_refresh_token = original_remove_refresh_token
        if hass.auth.async_create_access_token is _patched_create_access_token:
            hass.auth.async_create_access_token = original_create_access_token
        raise

    domain_data["_remove_refresh_token_original"] = original_remove_refresh_token
    domain_data["_remove_refresh_token_patched"] = _patched_remove_refresh_token
    domain_data["_create_access_token_original"] = original_create_access_token
    domain_data["_create_access_token_patched"] = _patched_create_access_token
    domain_data["_route_restore_callbacks"] = restore_callbacks
    domain_data["_runtime_patches_active"] = True


def _restore_runtime_patches(hass: HomeAssistant) -> None:
    """Restore every Home Assistant method and route independently."""
    domain_data = hass.data.get(DOMAIN, {})
    was_active = domain_data.pop("_runtime_patches_active", False)
    original_remove = domain_data.pop("_remove_refresh_token_original", None)
    patched_remove = domain_data.pop("_remove_refresh_token_patched", None)
    original_create = domain_data.pop("_create_access_token_original", None)
    patched_create = domain_data.pop("_create_access_token_patched", None)
    restore_callbacks = domain_data.pop("_route_restore_callbacks", [])

    if (
        not was_active
        and original_remove is None
        and original_create is None
        and not restore_callbacks
    ):
        return

    if original_create is not None:
        if (
            patched_create is None
            or hass.auth.async_create_access_token is patched_create
        ):
            hass.auth.async_create_access_token = original_create
        else:
            _LOGGER.warning(
                "Home Assistant access-token handler changed after OpenID setup; "
                "leaving the newer handler in place"
            )

    if original_remove is not None:
        if (
            patched_remove is None
            or hass.auth.async_remove_refresh_token is patched_remove
        ):
            hass.auth.async_remove_refresh_token = original_remove
        else:
            _LOGGER.warning(
                "Home Assistant refresh-token handler changed after OpenID setup; "
                "leaving the newer handler in place"
            )

    for restore in reversed(restore_callbacks):
        try:
            restore()
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Failed to restore an OpenID route patch")


async def _async_setup_shared(hass: HomeAssistant) -> None:
    """Set up shared OpenID runtime resources."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    if domain_data.get(DATA_SHARED_INITIALIZED):
        # The provider is deliberately removed during unload. Views and static
        # resources remain process-global, so a reload only needs to restore the
        # provider when it is no longer registered.
        provider = domain_data.get(DATA_AUTH_PROVIDER)
        providers = getattr(hass.auth, "_providers", None)  # noqa: SLF001
        if (
            not isinstance(providers, dict)
            or providers.get((DOMAIN, None)) is not provider
        ):
            domain_data[DATA_AUTH_PROVIDER] = await async_register_auth_provider(hass)
        return

    hass.data.setdefault("_openid_state", {})
    hass.data.setdefault("_openid_android_callbacks", {})

    authorize_path = hass_frontend.where() / "authorize.html"
    domain_data["authorize_template"] = await asyncio.to_thread(
        authorize_path.read_text, encoding="utf-8"
    )

    consent_path = Path(__file__).parent / "consent_template.html"
    domain_data["consent_template"] = await asyncio.to_thread(
        consent_path.read_text, encoding="utf-8"
    )

    error_path = Path(__file__).parent / "error_template.html"
    domain_data["error_template"] = await asyncio.to_thread(
        error_path.read_text, encoding="utf-8"
    )

    android_waiting_path = Path(__file__).parent / "android_waiting_template.html"
    domain_data["android_waiting_template"] = await asyncio.to_thread(
        android_waiting_path.read_text, encoding="utf-8"
    )

    android_completed_path = Path(__file__).parent / "android_completed_template.html"
    domain_data["android_completed_template"] = await asyncio.to_thread(
        android_completed_path.read_text, encoding="utf-8"
    )

    await hass.http.async_register_static_paths(
        [
            StaticPathConfig(
                "/openid/authorize.js",
                str(Path(__file__).parent / "authorize.js"),
                cache_headers=False,
            ),
            StaticPathConfig(
                "/openid/android-waiting.js",
                str(Path(__file__).parent / "android-waiting.js"),
                cache_headers=False,
            ),
            StaticPathConfig(
                "/openid/error.js",
                str(Path(__file__).parent / "error.js"),
                cache_headers=False,
            ),
            StaticPathConfig(
                "/openid/style.css",
                str(Path(__file__).parent / "style.css"),
                cache_headers=False,
            ),
            StaticPathConfig(
                "/openid/logout.js",
                str(Path(__file__).parent / "logout.js"),
                cache_headers=False,
            ),
        ]
    )

    add_extra_js_url(hass, "/openid/logout.js")

    hass.http.register_view(openid_views.OpenIDAuthorizeView(hass))
    hass.http.register_view(openid_views.OpenIDCallbackView(hass))
    hass.http.register_view(openid_views.OpenIDConsentView(hass))
    hass.http.register_view(openid_views.OpenIDAndroidStatusView(hass))
    hass.http.register_view(openid_views.OpenIDSessionView(hass))
    hass.http.register_view(openid_views.OpenIDLogoutView(hass))
    hass.http.register_view(openid_views.OpenIDBackchannelLogoutView(hass))

    domain_data[DATA_AUTH_PROVIDER] = await async_register_auth_provider(hass)
    domain_data[DATA_SHARED_INITIALIZED] = True
