"""OpenID / OAuth2 login component for Home Assistant."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import hass_frontend
import voluptuous as vol

from homeassistant.auth import InvalidAuthError, InvalidProvider
from homeassistant.auth.models import Credentials
from homeassistant.components.frontend import add_extra_js_url
from homeassistant.components.http import StaticPathConfig
from homeassistant.config_entries import SOURCE_IMPORT, ConfigEntry
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from . import views as openid_views
from .auth_provider import async_register_auth_provider
from .config_helpers import (
    async_discover_configuration,
    get_active_config,
    set_active_config,
    validate_runtime_provider_urls,
)
from .const import (
    CONF_ALLOW_LEGACY_OAUTH,
    CONF_AUTHORIZE_URL,
    CONF_BLOCK_LOGIN,
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

_LOGGER = logging.getLogger(__name__)

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
        except Exception as err:  # noqa: BLE001
            raise ConfigEntryNotReady(
                "OpenID provider discovery is not currently available"
            ) from err
    set_active_config(hass, runtime_config)
    try:
        _activate_runtime_patches(hass)
    except Exception as err:  # noqa: BLE001
        set_active_config(hass, None)
        raise ConfigEntryNotReady(
            "OpenID is incompatible with the current Home Assistant authentication routes"
        ) from err
    hass.data[DOMAIN][DATA_ACTIVE_ENTRY_ID] = entry.entry_id
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload an OpenID config entry."""
    domain_data = hass.data.get(DOMAIN)
    if not domain_data:
        return True

    if domain_data.get(DATA_ACTIVE_ENTRY_ID) == entry.entry_id:
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
        needs_discovery = (
            any(
                not config.get(key)
                for key in (CONF_AUTHORIZE_URL, CONF_TOKEN_URL, CONF_USER_INFO_URL)
            )
            or CONF_USE_PKCE not in config
            or (
                openid_requested
                and any(
                    not config.get(key)
                    for key in (
                        CONF_ISSUER,
                        CONF_JWKS_URL,
                        CONF_ID_TOKEN_SIGNING_ALGORITHMS,
                    )
                )
            )
        )
        if needs_discovery:
            discovered = await async_discover_configuration(
                hass,
                config[CONF_CONFIGURE_URL],
                validate_tls=bool(
                    config.get(CONF_VALIDATE_TLS, DEFAULT_VALIDATE_TLS)
                ),
                expected_issuer=config.get(CONF_ISSUER),
            )
            for key in (CONF_AUTHORIZE_URL, CONF_TOKEN_URL, CONF_USER_INFO_URL):
                if not config.get(key) and discovered.get(key):
                    config[key] = discovered[key]

            if not config.get(CONF_LOGOUT_URL) and discovered.get(CONF_LOGOUT_URL):
                config[CONF_LOGOUT_URL] = discovered[CONF_LOGOUT_URL]

            for key in (
                CONF_ISSUER,
                CONF_JWKS_URL,
                CONF_ID_TOKEN_SIGNING_ALGORITHMS,
            ):
                if not config.get(key) and discovered.get(key):
                    config[key] = discovered[key]

            if CONF_USE_PKCE not in config:
                config[CONF_USE_PKCE] = bool(discovered[DISCOVERY_PKCE_AVAILABLE])

    required_keys = [CONF_AUTHORIZE_URL, CONF_TOKEN_URL, CONF_USER_INFO_URL]
    if openid_requested:
        required_keys.extend((CONF_ISSUER, CONF_JWKS_URL))
        config.setdefault(CONF_ID_TOKEN_SIGNING_ALGORITHMS, ["RS256"])

    missing = [key for key in required_keys if not config.get(key)]
    if missing:
        source = "discovery" if CONF_CONFIGURE_URL in config else "manual configuration"
        raise RuntimeError(
            f"OpenID {source} did not provide required values: {', '.join(missing)}"
        )

    validate_runtime_provider_urls(config)
    return config


def _activate_runtime_patches(hass: HomeAssistant) -> None:
    """Install runtime monkey patches atomically while config is active."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    if domain_data.get("_runtime_patches_active"):
        return

    async def _async_notify_idp_logout(credential: Credentials) -> None:
        """Clear logout-related metadata from credentials."""
        config = get_active_config(hass)
        logout_url: str | None = config.get(CONF_LOGOUT_URL) if config else None
        if not logout_url:
            return

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

    def _patched_remove_refresh_token(refresh_token: Any) -> None:
        credential = getattr(refresh_token, "credential", None)
        if (
            credential is not None
            and getattr(credential, "auth_provider_type", None) == DOMAIN
        ):
            config = get_active_config(hass)
            logout_url = config.get(CONF_LOGOUT_URL) if config else None
            has_logout_metadata = any(
                credential.data.get(key)
                for key in (
                    CRED_ID_TOKEN,
                    CRED_SESSION_STATE,
                    CRED_LOGOUT_REDIRECT_URI,
                )
            )
            if logout_url and has_logout_metadata:
                hass.async_create_background_task(
                    _async_notify_idp_logout(credential),
                    name="openid_notify_idp_logout",
                )

        original_remove_refresh_token(refresh_token)

    def _patched_create_access_token(
        refresh_token: Any,
        remote_ip: str | None = None,
    ) -> str:
        """Reject and revoke tokens whose original auth provider was removed."""
        try:
            return original_create_access_token(refresh_token, remote_ip)
        except InvalidProvider as err:
            credential = getattr(refresh_token, "credential", None)
            provider_type = getattr(credential, "auth_provider_type", None)
            provider_id = getattr(credential, "auth_provider_id", None)
            _LOGGER.warning(
                "Removing stale refresh token for unavailable auth provider %s, %s",
                provider_type,
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
                cache_headers=True,
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

    domain_data[DATA_AUTH_PROVIDER] = await async_register_auth_provider(hass)
    domain_data[DATA_SHARED_INITIALIZED] = True
