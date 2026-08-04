"""OpenID Connect views for Home Assistant."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from contextlib import suppress
from hashlib import sha256
from html import escape
from http import HTTPStatus
import json
import logging
import secrets
from string import Template
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from aiohttp import ClientSession
from aiohttp.web import Request, Response
from yarl import URL

from homeassistant.auth.const import GROUP_ID_ADMIN, GROUP_ID_USER
from homeassistant.auth.models import User
from homeassistant.components.auth import create_auth_code, indieauth
from homeassistant.components.http import KEY_HASS_USER, HomeAssistantView
from homeassistant.components.person import DOMAIN as PERSON_DOMAIN, async_create_person
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.helpers.network import NoURLAvailableError, get_url
from homeassistant.util import slugify

from .account_linker import (
    AccountLinkError,
    AmbiguousAccountError,
    async_find_user_by_username,
    async_resolve_user,
)
from .auth_provider import (
    OpenIDAmbiguousIdentityError,
    OpenIDIdentityConflictError,
)
from .auth_service import (
    ProviderAuthenticationError,
    async_exchange_and_validate_identity,
)
from .config_helpers import get_active_config
from .identity import normalize_username
from .const import (
    CONF_AUTHORIZE_URL,
    CONF_BLOCK_LOGIN,
    CONF_CREATE_USER,
    CONF_ERROR_URL,
    CONF_ID_TOKEN_SIGNING_ALGORITHMS,
    CONF_ISSUER,
    CONF_JWKS_URL,
    CONF_LOGOUT_URL,
    CONF_POST_LOGOUT_URL,
    CONF_SCOPE,
    CONF_TOKEN_URL,
    CONF_USE_HEADER_AUTH,
    CONF_USE_PKCE,
    CONF_USER_INFO_URL,
    CONF_USERNAME_FIELD,
    CONF_VALIDATE_TLS,
    CRED_ID_TOKEN,
    CRED_ISSUER,
    CRED_LOGOUT_REDIRECT_URI,
    CRED_SESSION_ID,
    CRED_SESSION_STATE,
    CRED_SUBJECT,
    DOMAIN,
)
from .http_security import html_response, json_response, redirect_response
from .oidc_helper import async_validate_logout_token
from .state_store import (
    ANDROID_STATE_STORE,
    ANDROID_STATE_TTL,
    LOGOUT_STATE_STORE,
    LOGOUT_STATE_TTL,
    LOGOUT_TOKEN_JTI_STORE,
    LOGOUT_TOKEN_JTI_TTL,
    AUTH_STATE_STORE,
    CONSENT_STATE_STORE,
    StateStoreFull,
    check_rate_limit,
    get_pending,
    pop_pending,
    store_pending,
)

_LOGGER = logging.getLogger(__name__)

_PKCE_VERIFIER_KEY = "pkce_code_verifier"
_OIDC_NONCE_KEY = "oidc_nonce"
_ANDROID_TRANSACTION_KEY = "android_transaction_id"
_ANDROID_POLL_COOKIE = "openid_android_poll"
_ALLOWED_PROMPTS = {"login", "consent", "select_account"}


def _short_id(value: str | None) -> str:
    """Return a safe correlation identifier for logs."""
    return f"{value[:8]}..." if value else "<missing>"


async def _validate_client_request(
    hass: HomeAssistant, params: Mapping[str, str]
) -> bool:
    """Validate the Home Assistant OAuth client and exact redirect URI."""
    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    if not client_id or not redirect_uri or not indieauth.verify_client_id(client_id):
        return False
    return await indieauth.verify_redirect_uri(hass, client_id, redirect_uri)


def _url_origin(value: str | None) -> tuple[str, str, int] | None:
    """Return a normalized HTTP(S) origin for an absolute URL."""
    if not value:
        return None

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not hostname:
        return None

    if port is None:
        port = 443 if scheme == "https" else 80

    return scheme, hostname.rstrip(".").lower(), port


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier and code_challenge pair."""
    code_verifier = secrets.token_urlsafe(96)[:128]
    digest = sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _configured_callback_base_url(hass: HomeAssistant) -> str:
    """Return a Home Assistant configured URL for the provider callback."""
    with suppress(NoURLAvailableError):
        return get_url(
            hass,
            allow_internal=False,
            allow_external=True,
            prefer_external=True,
        )

    return get_url(
        hass,
        allow_internal=True,
        allow_external=False,
        allow_cloud=False,
    )


def _android_waiting_response(
    hass: HomeAssistant,
    request: Request,
    authorize_url: str,
    transaction_id: str,
    poll_secret: str,
) -> Response:
    """Return Android waiting page that polls for callback completion."""
    template_content = hass.data[DOMAIN]["android_waiting_template"]
    template = Template(template_content)
    html = template.substitute(
        authorize_url=escape(authorize_url, quote=True),
        transaction_id=escape(transaction_id, quote=True),
    )
    response = html_response(html)
    response.set_cookie(
        _ANDROID_POLL_COOKIE,
        poll_secret,
        max_age=ANDROID_STATE_TTL,
        httponly=True,
        secure=request.secure,
        samesite="Lax",
        path="/auth/openid/android/status",
    )
    return response


def _is_android_client(client_id: str | None) -> bool:
    """Return whether request is from the Home Assistant Android client."""
    return client_id == "https://home-assistant.io/android"


def _request_rate_key(request: Request, purpose: str, client_id: str = "") -> str:
    """Return a non-secret key for public authentication rate limits."""
    remote = request.remote or "unknown"
    return f"{purpose}:{remote}:{client_id[:256]}"


def _request_parameters_are_bounded(params: Mapping[str, str]) -> bool:
    """Reject unexpectedly large public OAuth parameters."""
    limits = {
        "state": 4096,
        "client_state": 4096,
        "client_id": 2048,
        "redirect_uri": 4096,
        "prompt": 64,
    }
    return all(
        not isinstance(params.get(key), str) or len(params[key]) <= maximum
        for key, maximum in limits.items()
    )


async def _begin_provider_authorization(
    hass: HomeAssistant,
    request: Request,
    params: Mapping[str, str],
    conf: Mapping[str, Any],
) -> Response:
    """Create a server-side transaction and redirect to the provider."""
    stored_params = dict(params)
    client_id = stored_params.get("client_id")
    if not check_rate_limit(
        hass,
        _request_rate_key(request, "authorize", client_id or ""),
        limit=30,
        window=5 * 60,
    ):
        return html_response(
            "Too many OpenID sign-in attempts; try again shortly",
            status=HTTPStatus.TOO_MANY_REQUESTS,
        )
    client_state = stored_params.get("client_state") or stored_params.get("state")
    if client_state:
        stored_params["client_state"] = client_state

    try:
        base_url = _configured_callback_base_url(hass)
    except NoURLAvailableError:
        return html_response(
            "Home Assistant has no configured internal or external URL",
            status=HTTPStatus.SERVICE_UNAVAILABLE,
        )

    stored_params["base_url"] = base_url
    redirect_uri = str(URL(base_url).with_path("/auth/openid/callback"))
    internal_state = secrets.token_urlsafe(32)
    query: dict[str, str] = {
        "response_type": "code",
        "client_id": conf[CONF_CLIENT_ID],
        "redirect_uri": redirect_uri,
        "scope": conf.get(CONF_SCOPE, ""),
        "state": internal_state,
    }

    prompt = stored_params.get("prompt")
    if prompt in _ALLOWED_PROMPTS:
        query["prompt"] = prompt

    if "openid" in conf.get(CONF_SCOPE, "").split():
        nonce = secrets.token_urlsafe(32)
        stored_params[_OIDC_NONCE_KEY] = nonce
        query["nonce"] = nonce

    if conf.get(CONF_USE_PKCE, False):
        code_verifier, code_challenge = _generate_pkce_pair()
        stored_params[_PKCE_VERIFIER_KEY] = code_verifier
        query["code_challenge"] = code_challenge
        query["code_challenge_method"] = "S256"

    android_transaction_id: str | None = None
    poll_secret: str | None = None
    if _is_android_client(client_id):
        android_transaction_id = secrets.token_urlsafe(32)
        poll_secret = secrets.token_urlsafe(32)
        stored_params[_ANDROID_TRANSACTION_KEY] = android_transaction_id
        try:
            store_pending(
                hass,
                ANDROID_STATE_STORE,
                android_transaction_id,
                {
                    "status": "pending",
                    "secret_hash": sha256(poll_secret.encode()).hexdigest(),
                },
                ttl=ANDROID_STATE_TTL,
            )
        except StateStoreFull:
            return html_response(
                "Too many OpenID sign-ins are pending; try again shortly",
                status=HTTPStatus.TOO_MANY_REQUESTS,
            )

    try:
        store_pending(hass, AUTH_STATE_STORE, internal_state, stored_params)
    except StateStoreFull:
        if android_transaction_id:
            pop_pending(
                hass,
                ANDROID_STATE_STORE,
                android_transaction_id,
                ttl=ANDROID_STATE_TTL,
            )
        return html_response(
            "Too many OpenID sign-ins are pending; try again shortly",
            status=HTTPStatus.TOO_MANY_REQUESTS,
        )

    provider_url = str(URL(conf[CONF_AUTHORIZE_URL]).update_query(query))
    if android_transaction_id and poll_secret:
        return _android_waiting_response(
            hass,
            request,
            provider_url,
            android_transaction_id,
            poll_secret,
        )
    return redirect_response(provider_url)


class OpenIDAuthorizeView(HomeAssistantView):
    """Redirect to the IdP’s authorisation endpoint."""

    name = "api:openid:authorize"
    url = "/auth/openid/authorize"
    requires_auth = False

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the authorisation view."""
        self.hass = hass

    def should_show_consent_screen(self, params: Mapping[str, str]) -> bool:
        """Determine whether to show the consent screen."""
        conf = get_active_config(self.hass)
        if not conf:
            return False

        if not conf.get(CONF_BLOCK_LOGIN, False):
            _LOGGER.debug(
                "block_login is disabled; skipping consent screen. HA will handle consent if needed"
            )
            return False

        client_id = params.get("client_id")
        internal_url = None
        external_url = None
        cloud_url = None

        with suppress(NoURLAvailableError):
            internal_url = get_url(
                self.hass, allow_internal=True, allow_external=False, allow_cloud=False
            )

        with suppress(NoURLAvailableError):
            external_url = get_url(
                self.hass,
                allow_internal=False,
                allow_external=True,
                prefer_external=True,
            )

        with suppress(NoURLAvailableError):
            cloud_url = get_url(self.hass, allow_internal=False, require_cloud=True)

        client_origin = _url_origin(client_id)
        trusted_origins = {
            origin
            for url in (external_url, internal_url, cloud_url)
            if (origin := _url_origin(url)) is not None
        }
        if client_origin is not None and client_origin in trusted_origins:
            _LOGGER.debug(
                "Request from Home Assistant frontend detected; skipping consent screen"
            )
            return False

        return True

    async def get(self, request: Request) -> Response:
        """Redirect the browser to the IdP’s authorisation endpoint."""
        conf = get_active_config(self.hass)
        if conf is None:
            return _show_error(
                self.hass,
                request.rel_url.query,
                alert_type="error",
                alert_message="OpenID login failed! Integration is not configured.",
            )

        params = dict(request.rel_url.query)
        if not _request_parameters_are_bounded(params):
            return Response(status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        if not await _validate_client_request(self.hass, params):
            _LOGGER.warning("Rejected invalid OAuth client or redirect URI")
            return Response(
                status=HTTPStatus.FORBIDDEN,
                text="Invalid OAuth client or redirect URI",
            )

        if self.should_show_consent_screen(params):
            _LOGGER.info(
                "Showing consent screen for client_id: %s", params.get("client_id")
            )
            return await self._show_consent_screen(request, params)

        return await _begin_provider_authorization(
            self.hass, request, params, conf
        )


    async def _show_consent_screen(
        self, request: Request, params: Mapping[str, str]
    ) -> Response:
        """Show the OAuth consent screen to the user."""
        consent_state = secrets.token_urlsafe(24)
        store_pending(
            self.hass,
            CONSENT_STATE_STORE,
            consent_state,
            dict(params),
        )

        client_state = params.get("client_state") or params.get("state") or ""
        template = Template(self.hass.data[DOMAIN]["consent_template"])
        html = template.substitute(
            state=escape(consent_state, quote=True),
            client_id=escape(
                params.get("client_id", "Unknown Application"), quote=True
            ),
            redirect_uri=escape(params.get("redirect_uri", ""), quote=True),
            base_url=escape(params.get("base_url", ""), quote=True),
            client_state=escape(client_state, quote=True),
            cancel_url="/",
        )
        return html_response(html)


class OpenIDConsentView(HomeAssistantView):
    """Handle consent form submission."""

    name = "api:openid:consent"
    url = "/auth/openid/consent"
    requires_auth = False

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the consent view."""
        self.hass = hass

    async def post(self, request: Request) -> Response:
        """Handle consent form submission."""
        conf = get_active_config(self.hass)
        if conf is None:
            return Response(
                status=HTTPStatus.SERVICE_UNAVAILABLE,
                text="OpenID integration is not configured",
            )

        form_data = await request.post()

        consent_state = form_data.get("state")
        if not consent_state:
            _LOGGER.error("Consent form submitted without state")
            return Response(status=HTTPStatus.BAD_REQUEST, text="Invalid request")

        original_params = pop_pending(
            self.hass, CONSENT_STATE_STORE, str(consent_state)
        )

        if not original_params:
            _LOGGER.error("Invalid or expired consent state %s", _short_id(str(consent_state)))
            return Response(
                status=HTTPStatus.BAD_REQUEST, text="Invalid or expired consent"
            )

        if not await _validate_client_request(self.hass, original_params):
            _LOGGER.warning("Rejected invalid OAuth client after consent")
            return Response(
                status=HTTPStatus.FORBIDDEN,
                text="Invalid OAuth client or redirect URI",
            )

        _LOGGER.info("User authorized the validated OAuth client")
        return await _begin_provider_authorization(
            self.hass, request, original_params, conf
        )


class OpenIDCallbackView(HomeAssistantView):
    """Handle the callback from the IdP after authorisation."""

    name = "api:openid:callback"
    url = "/auth/openid/callback"
    requires_auth = False

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the callback view."""
        self.hass = hass

    async def get(self, request: Request) -> Response:  # noqa: C901
        """Handle redirect from IdP, exchange code for tokens."""
        params = dict(request.rel_url.query)
        code = params.get("code")
        state = params.get("state")

        if not code or not state:
            _LOGGER.warning("OpenID callback was missing code or state")
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message="OpenID login failed! Missing code or state parameter.",
            )

        pending = pop_pending(self.hass, AUTH_STATE_STORE, state)
        if not pending:
            _LOGGER.warning("Invalid or expired OpenID state %s", _short_id(state))
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message="OpenID login failed! Invalid state parameter.",
            )

        oauth_client_state = pending.get("client_state") or pending.get("state")
        params = {**params, **pending}
        if not await _validate_client_request(self.hass, params):
            _LOGGER.warning("Rejected invalid OAuth client during callback")
            return Response(
                status=HTTPStatus.FORBIDDEN,
                text="Invalid OAuth client or redirect URI",
            )
        params["_validated_redirect_uri"] = params["redirect_uri"]

        conf = get_active_config(self.hass)
        if conf is None:
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message="OpenID login failed! Integration is not configured.",
            )

        base_url = params.get("base_url", "")
        redirect_uri = str(URL(base_url).with_path("/auth/openid/callback"))

        try:
            identity = await async_exchange_and_validate_identity(
                self.hass,
                config=conf,
                code=code,
                redirect_uri=redirect_uri,
                nonce=params.get(_OIDC_NONCE_KEY),
                code_verifier=params.get(_PKCE_VERIFIER_KEY),
            )
        except ProviderAuthenticationError as err:
            _LOGGER.warning(
                "Provider identity validation failed for transaction %s: %s",
                _short_id(state),
                err,
            )
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message=err.public_message,
            )

        token_data = identity.token_data
        username = identity.username
        new_credential_fields = identity.credential_fields

        provider = self.hass.data[DOMAIN].get("auth_provider")
        if provider is None:
            _LOGGER.error("OpenID auth provider not registered")
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message="OpenID login failed! Auth provider not available.",
            )

        try:
            credentials = await provider.async_get_or_create_credentials(
                new_credential_fields
            )
        except OpenIDIdentityConflictError as err:
            _LOGGER.warning("Refusing OIDC identity rebind: %s", err)
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message=(
                    "OpenID login failed! This username is already linked to a different identity."
                ),
            )
        except OpenIDAmbiguousIdentityError as err:
            _LOGGER.warning("Refusing ambiguous OpenID identity: %s", err)
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message=(
                    "OpenID login failed! More than one credential matches this identity."
                ),
            )
        except ValueError as err:  # pragma: no cover - defensive guard
            _LOGGER.error("Failed to obtain credentials: %s", err)
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message="OpenID login failed! Could not map credentials.",
            )

        credential_data = dict(credentials.data)
        credential_data.update(new_credential_fields)

        postlogout_url = conf.get(CONF_POST_LOGOUT_URL)

        self._store_logout_metadata(
            credential_data,
            token_data,
            params,
            postlogout_url,
        )

        try:
            user = await async_resolve_user(
                self.hass,
                credentials=credentials,
                credential_data=credential_data,
                create_user=bool(conf.get(CONF_CREATE_USER, False)),
            )
        except AmbiguousAccountError as err:
            _LOGGER.warning("Refusing ambiguous username match: %s", err)
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message=(
                    "OpenID login failed! More than one Home Assistant account has credentials matching this username."
                ),
            )
        except AccountLinkError as err:
            _LOGGER.error("Home Assistant account linking failed: %s", err)
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message=(
                    "OpenID login failed! The matching Home Assistant account could not be linked."
                ),
            )

        if user is None:
            _LOGGER.warning("OpenID user did not match a Home Assistant account")
            return _show_error(
                self.hass,
                params,
                alert_type="error",
                alert_message=(
                    "OpenID login succeeded, but no matching Home Assistant account was found. "
                    "Ask your administrator to add your account or enable automatic user creation."
                ),
            )

        display_name = (
            credential_data.get("name")
            or credential_data.get("preferred_username")
            or credential_data.get("username")
        )
        if display_name and not user.name:
            await self.hass.auth.async_update_user(user, name=display_name)

        groups_initialized = credential_data.get("openid_groups_initialized", False)
        if not groups_initialized:
            credential_data["openid_groups_initialized"] = True
            if not user.is_owner:
                current_group_ids = [group.id for group in user.groups]
                new_group_ids = [
                    gid for gid in current_group_ids if gid != GROUP_ID_ADMIN
                ]
                changed = len(new_group_ids) != len(current_group_ids)
                if GROUP_ID_USER not in new_group_ids:
                    new_group_ids.append(GROUP_ID_USER)
                    changed = True
                if changed:
                    await self.hass.auth.async_update_user(
                        user, group_ids=new_group_ids
                    )

        self.hass.auth.async_update_user_credentials_data(credentials, credential_data)

        await self._ensure_person_for_user(user, credential_data)

        client_id = params["client_id"]
        url = params["redirect_uri"]
        _LOGGER.debug("User %s authenticated via OpenID", username)
        result = create_auth_code(self.hass, client_id, credentials)

        _LOGGER.debug("Created Home Assistant authorization code")
        callback_url = self._build_callback_url(url, result, oauth_client_state)

        if transaction_id := params.get(_ANDROID_TRANSACTION_KEY):
            android_entry = get_pending(
                self.hass,
                ANDROID_STATE_STORE,
                transaction_id,
                ttl=ANDROID_STATE_TTL,
            )
            if android_entry:
                android_entry.update(
                    {"status": "completed", "callback_url": callback_url}
                )
                store_pending(
                    self.hass,
                    ANDROID_STATE_STORE,
                    transaction_id,
                    android_entry,
                    ttl=ANDROID_STATE_TTL,
                )
            return self._android_completed_response()

        return Response(status=HTTPStatus.FOUND, headers={"Location": callback_url})

    @staticmethod
    def _build_callback_url(
        redirect_uri: str, auth_code: str, oauth_client_state: str | None
    ) -> str:
        """Build callback URL with auth parameters."""
        parsed_url = URL(redirect_uri)
        existing_params = dict(parsed_url.query)

        callback_params: dict[str, str | int] = {
            "auth_callback": 1,
            "code": auth_code,
            "storeToken": "true",
        }

        callback_params["provider_id"] = "homeassistant"
        callback_params["state"] = (
            oauth_client_state or secrets.token_urlsafe(16)
        )

        all_params = {**existing_params, **callback_params}
        callback_url = str(parsed_url.with_query(all_params))
        return callback_url

    def _android_completed_response(self) -> Response:
        """Return completion page for Android polling flow."""
        template_content = self.hass.data[DOMAIN]["android_completed_template"]
        return html_response(template_content)

    @staticmethod
    def _store_logout_metadata(
        credential_data: dict[str, Any],
        token_data: dict[str, Any] | None,
        params: Mapping[str, Any],
        postlogout_redirect_url: str | None,
    ) -> None:
        """Persist logout-related metadata for future IdP notifications."""

        if token_data and (id_token := token_data.get("id_token")):
            credential_data[CRED_ID_TOKEN] = id_token
        else:
            credential_data.pop(CRED_ID_TOKEN, None)

        if session_state_param := params.get("session_state"):
            credential_data[CRED_SESSION_STATE] = session_state_param
        elif token_data and (session_state := token_data.get("session_state")):
            credential_data[CRED_SESSION_STATE] = session_state
        else:
            credential_data.pop(CRED_SESSION_STATE, None)

        if postlogout_redirect_url:
            credential_data[CRED_LOGOUT_REDIRECT_URI] = postlogout_redirect_url
        else:
            credential_data.pop(CRED_LOGOUT_REDIRECT_URI, None)

    async def _ensure_person_for_user(
        self, user: User, credential_data: dict[str, Any]
    ) -> None:
        """Create a person entry for the user if needed."""
        if PERSON_DOMAIN not in self.hass.data:
            _LOGGER.debug("Person component not loaded; skipping person creation")
            return

        _, storage_collection, _ = self.hass.data[PERSON_DOMAIN]
        items = storage_collection.async_items()

        if any(item.get("user_id") == user.id for item in items):
            return

        candidate_name = (
            credential_data.get("name")
            or credential_data.get("preferred_username")
            or credential_data.get("username")
            or user.name
        )

        if candidate_name:
            slug_candidate = slugify(candidate_name)
            for item in items:
                item_name = item.get("name")
                item_id = item.get("id")
                if (
                    isinstance(item_name, str)
                    and item_name.lower() == candidate_name.lower()
                ) or (
                    slug_candidate
                    and isinstance(item_id, str)
                    and item_id == slug_candidate
                ):
                    if item.get("user_id") != user.id:
                        await storage_collection.async_update_item(
                            item["id"],
                            {"user_id": user.id},
                        )
                    return

        person_name = candidate_name or user.id

        try:
            await async_create_person(self.hass, person_name, user_id=user.id)
        except ValueError as err:
            _LOGGER.warning("Unable to create person for user %s: %s", user.id, err)

    async def _async_find_user_by_username(self, username: str) -> User | None:
        """Compatibility wrapper for credential-only username matching."""
        return await async_find_user_by_username(self.hass, username)


class OpenIDSessionView(HomeAssistantView):
    """Create a short-lived server-side IdP logout ticket."""

    name = "api:openid:session"
    url = "/auth/openid/session"
    requires_auth = True

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the session view."""
        self.hass = hass

    async def get(self, request: Request) -> Response:
        """Return only an opaque same-origin logout path to the frontend."""
        conf = get_active_config(self.hass)
        if not conf or not conf.get(CONF_LOGOUT_URL):
            return Response(status=HTTPStatus.NO_CONTENT)

        user: User = request[KEY_HASS_USER]
        credentials = [
            candidate
            for candidate in user.credentials
            if candidate.auth_provider_type == DOMAIN
        ]
        if not credentials:
            return Response(status=HTTPStatus.NO_CONTENT)

        # Prefer the credential with current logout metadata. Ambiguity is
        # rejected rather than exposing a token belonging to an arbitrary IdP
        # session.
        candidates = [
            candidate
            for candidate in credentials
            if candidate.data.get(CRED_ID_TOKEN)
            or candidate.data.get(CRED_SESSION_STATE)
        ]
        if len(candidates) != 1:
            return Response(status=HTTPStatus.NO_CONTENT)
        credential = candidates[0]

        params: dict[str, str] = {}
        if id_token := credential.data.get(CRED_ID_TOKEN):
            params["id_token_hint"] = id_token
        if session_state := credential.data.get(CRED_SESSION_STATE):
            params["session_state"] = session_state
        if redirect_uri := credential.data.get(CRED_LOGOUT_REDIRECT_URI):
            params["post_logout_redirect_uri"] = redirect_uri
        if "id_token_hint" not in params and "session_state" not in params:
            if client_id := conf.get(CONF_CLIENT_ID):
                params["client_id"] = client_id

        target = str(URL(conf[CONF_LOGOUT_URL]).update_query(params))
        ticket = secrets.token_urlsafe(32)
        try:
            store_pending(
                self.hass,
                LOGOUT_STATE_STORE,
                ticket,
                {"target": target, "user_id": user.id},
                ttl=LOGOUT_STATE_TTL,
            )
        except StateStoreFull:
            return json_response(
                {"error": "too_many_pending_logouts"},
                status=HTTPStatus.TOO_MANY_REQUESTS,
            )

        return json_response({"logout_path": f"/auth/openid/logout?ticket={ticket}"})


class OpenIDLogoutView(HomeAssistantView):
    """Consume a one-use logout ticket and redirect to the IdP."""

    name = "api:openid:logout"
    url = "/auth/openid/logout"
    requires_auth = False

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the logout view."""
        self.hass = hass

    async def get(self, request: Request) -> Response:
        """Consume an opaque logout ticket without exposing ID tokens to JS."""
        ticket = request.rel_url.query.get("ticket")
        if not ticket:
            return html_response(
                "Invalid or expired logout request",
                status=HTTPStatus.BAD_REQUEST,
            )
        pending = pop_pending(
            self.hass,
            LOGOUT_STATE_STORE,
            ticket,
            ttl=LOGOUT_STATE_TTL,
        )
        target = pending.get("target") if pending else None
        if not isinstance(target, str):
            return html_response(
                "Invalid or expired logout request",
                status=HTTPStatus.BAD_REQUEST,
            )
        return redirect_response(target)


class OpenIDBackchannelLogoutView(HomeAssistantView):
    """Receive signed OIDC back-channel logout notifications."""

    name = "api:openid:backchannel_logout"
    url = "/auth/openid/backchannel_logout"
    requires_auth = False

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the back-channel logout view."""
        self.hass = hass

    async def post(self, request: Request) -> Response:
        """Validate a logout token and revoke matching HA refresh tokens."""
        if request.content_length is not None and request.content_length > 65536:
            return Response(status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        conf = get_active_config(self.hass)
        if not conf or not all(
            conf.get(key)
            for key in (CONF_ISSUER, CONF_JWKS_URL, CONF_CLIENT_ID)
        ):
            return Response(status=HTTPStatus.NOT_FOUND)

        form = await request.post()
        logout_token = form.get("logout_token")
        if not isinstance(logout_token, str) or not logout_token:
            return Response(status=HTTPStatus.BAD_REQUEST)

        algorithms = conf.get(CONF_ID_TOKEN_SIGNING_ALGORITHMS, ["RS256"])
        if isinstance(algorithms, str):
            algorithms = [algorithms]
        try:
            claims = await async_validate_logout_token(
                self.hass,
                logout_token=logout_token,
                issuer=conf[CONF_ISSUER],
                jwks_url=conf[CONF_JWKS_URL],
                client_id=conf[CONF_CLIENT_ID],
                algorithms=list(algorithms),
                validate_tls=bool(conf.get(CONF_VALIDATE_TLS, True)),
            )
            jti = claims["jti"]
            if get_pending(
                self.hass,
                LOGOUT_TOKEN_JTI_STORE,
                jti,
                ttl=LOGOUT_TOKEN_JTI_TTL,
            ):
                return Response(status=HTTPStatus.BAD_REQUEST)
            store_pending(
                self.hass,
                LOGOUT_TOKEN_JTI_STORE,
                jti,
                {"used": True},
                ttl=LOGOUT_TOKEN_JTI_TTL,
            )
        except (ValueError, LookupError, StateStoreFull):
            _LOGGER.warning("Rejected invalid or replayed OIDC logout token")
            return Response(status=HTTPStatus.BAD_REQUEST)
        except Exception:
            _LOGGER.exception("Failed to validate OIDC logout token")
            return Response(status=HTTPStatus.SERVICE_UNAVAILABLE)

        subject = claims.get("sub")
        session_id = claims.get("sid")
        issuer = claims.get("iss")
        revoked = 0
        for user in await self.hass.auth.async_get_users():
            matching_credentials = [
                credential
                for credential in user.credentials
                if credential.auth_provider_type == DOMAIN
                and credential.data.get(CRED_ISSUER) == issuer
                and (
                    (subject is not None and credential.data.get(CRED_SUBJECT) == subject)
                    or (
                        session_id is not None
                        and credential.data.get(CRED_SESSION_ID) == session_id
                    )
                )
            ]
            if not matching_credentials:
                continue
            refresh_tokens = getattr(user, "refresh_tokens", {})
            tokens = (
                list(refresh_tokens.values())
                if isinstance(refresh_tokens, dict)
                else list(refresh_tokens)
            )
            for refresh_token in tokens:
                token_credential = getattr(refresh_token, "credential", None)
                if any(token_credential is candidate for candidate in matching_credentials):
                    self.hass.auth.async_remove_refresh_token(refresh_token)
                    revoked += 1

        _LOGGER.info("Processed OIDC back-channel logout; revoked %d session(s)", revoked)
        return Response(status=HTTPStatus.NO_CONTENT)


class OpenIDAndroidStatusView(HomeAssistantView):
    """Expose Android OpenID callback status for polling."""

    name = "api:openid:android_status"
    url = "/auth/openid/android/status"
    requires_auth = False

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the Android status view."""
        self.hass = hass

    async def get(self, request: Request) -> Response:
        """Return completion status for a given OAuth state."""
        transaction_id = request.rel_url.query.get("transaction")
        if not check_rate_limit(
            self.hass,
            _request_rate_key(request, "android-status", transaction_id or ""),
            limit=120,
            window=5 * 60,
        ):
            return json_response(
                {"status": "error", "message": "Too many requests"},
                status=HTTPStatus.TOO_MANY_REQUESTS,
            )
        poll_secret = request.cookies.get(_ANDROID_POLL_COOKIE)
        if not transaction_id or not poll_secret:
            return json_response(
                {"status": "error", "message": "Missing transaction proof"},
                status=HTTPStatus.FORBIDDEN,
            )

        entry = get_pending(
            self.hass,
            ANDROID_STATE_STORE,
            transaction_id,
            ttl=ANDROID_STATE_TTL,
        )
        if not entry:
            return json_response(
                {"status": "expired"},
                status=HTTPStatus.GONE,
            )

        expected_hash = entry.get("secret_hash")
        supplied_hash = sha256(poll_secret.encode()).hexdigest()
        if not isinstance(expected_hash, str) or not secrets.compare_digest(
            expected_hash, supplied_hash
        ):
            return json_response(
                {"status": "error", "message": "Invalid transaction proof"},
                status=HTTPStatus.FORBIDDEN,
            )

        if entry.get("status") == "completed" and entry.get("callback_url"):
            payload = {
                "status": "completed",
                "callback_url": entry["callback_url"],
            }
            pop_pending(
                self.hass,
                ANDROID_STATE_STORE,
                transaction_id,
                ttl=ANDROID_STATE_TTL,
            )
            response = json_response(payload)
            response.del_cookie(
                _ANDROID_POLL_COOKIE,
                path="/auth/openid/android/status",
            )
            return response

        return json_response({"status": "pending"})

def _show_error(
    hass: HomeAssistant,
    params: Mapping[str, str],
    alert_type: str,
    alert_message: str,
) -> Response:
    """Render an escaped error page with only a validated return target."""
    conf = get_active_config(hass) or {}
    error_url = conf.get(CONF_ERROR_URL)
    if isinstance(error_url, str):
        return redirect_response(
            str(
                URL(error_url).update_query(
                    {"alert_type": alert_type, "alert_message": alert_message}
                )
            )
        )

    redirect_url = params.get("_validated_redirect_uri") or "/auth/authorize"
    template = Template(hass.data[DOMAIN]["error_template"])
    html = template.substitute(
        alert_type=escape(alert_type, quote=True),
        alert_message=escape(alert_message, quote=True),
        redirect_url=escape(redirect_url, quote=True),
    )
    return html_response(html)
