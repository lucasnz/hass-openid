"""OpenID auth provider for Home Assistant."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol

from homeassistant.auth.auth_store import AuthStore
from homeassistant.auth.const import GROUP_ID_USER
from homeassistant.auth.models import (
    AuthFlowContext,
    AuthFlowResult,
    Credentials,
    UserMeta,
)
from homeassistant.auth.providers import (
    AUTH_PROVIDER_SCHEMA,
    AUTH_PROVIDERS,
    AuthProvider,
    LoginFlow,
)
from homeassistant.core import HomeAssistant

from .const import CRED_ISSUER, CRED_SUBJECT, DOMAIN
from .identity import normalize_username

OPENID_AUTH_PROVIDER_SCHEMA = AUTH_PROVIDER_SCHEMA.extend({}, extra=vol.ALLOW_EXTRA)
_LEGACY_CRED_SUBJECT = "subject"


class OpenIDIdentityConflictError(ValueError):
    """Raised when a username is already bound to another OIDC identity."""


class OpenIDAmbiguousIdentityError(ValueError):
    """Raised when more than one credential could own an identity."""


class OpenIDLoginFlow(LoginFlow["OpenIDAuthProvider"]):
    """Dummy login flow for OpenID provider."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> AuthFlowResult:
        """Abort: the flow is handled by the external OpenID exchange."""
        return self.async_abort(reason="external_auth_not_supported")


@AUTH_PROVIDERS.register(DOMAIN)
class OpenIDAuthProvider(AuthProvider):
    """Auth provider backing the hass-openid integration."""

    DEFAULT_TITLE = "OpenID Connect"
    CONFIG_SCHEMA = OPENID_AUTH_PROVIDER_SCHEMA

    async def async_login_flow(
        self, context: AuthFlowContext | None
    ) -> OpenIDLoginFlow:
        """Return a dummy login flow."""
        return OpenIDLoginFlow(self)

    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, Any]
    ) -> Credentials:
        """Resolve credentials by stable OIDC identity, then initial username."""
        username = normalize_username(flow_result.get("username"))
        issuer = flow_result.get(CRED_ISSUER)
        subject = flow_result.get(CRED_SUBJECT)
        if issuer is not None and not isinstance(issuer, str):
            raise ValueError("OIDC issuer must be a string")
        if subject is not None and not isinstance(subject, str):
            raise ValueError("OIDC subject must be a string")
        issuer = issuer.strip() if isinstance(issuer, str) else None
        subject = subject.strip() if isinstance(subject, str) else None
        if bool(issuer) != bool(subject):
            raise ValueError("OIDC issuer and subject must be supplied together")

        credential_data = dict(flow_result)
        credential_data["username"] = username
        if issuer and subject:
            credential_data[CRED_ISSUER] = issuer
            credential_data[CRED_SUBJECT] = subject

        credentials_list = list(await self.async_credentials())

        # Once linked, issuer + subject is authoritative. Username remains a
        # mutable account-mapping/display attribute and may legitimately change.
        stable_matches = [
            credentials
            for credentials in credentials_list
            if issuer
            and subject
            and credentials.data.get(CRED_ISSUER) == issuer
            and credentials.data.get(CRED_SUBJECT) == subject
        ]
        if len(stable_matches) > 1:
            raise OpenIDAmbiguousIdentityError(
                "Multiple OpenID credentials match the issuer and subject"
            )
        if stable_matches:
            credentials = stable_matches[0]
            # Defer all credential mutation until Home Assistant has resolved
            # and linked the user. AuthStore owns persisted object mutation.
            credentials.is_new = False
            return credentials

        username_matches: list[Credentials] = []
        for credentials in credentials_list:
            try:
                stored_username = normalize_username(
                    credentials.data.get("username")
                )
            except ValueError:
                continue
            if stored_username == username:
                username_matches.append(credentials)

        if len(username_matches) > 1:
            raise OpenIDAmbiguousIdentityError(
                "Multiple OpenID credentials match the username"
            )
        if username_matches:
            credentials = username_matches[0]
            stored_issuer = credentials.data.get(CRED_ISSUER)
            stored_subject = credentials.data.get(CRED_SUBJECT)
            legacy_subject = credentials.data.get(_LEGACY_CRED_SUBJECT)

            # Permit a one-time migration of credentials created before stable
            # issuer binding was introduced. The old integration did persist
            # ``subject``; require that value to match before binding an issuer.
            if stored_issuer or stored_subject:
                if not issuer or not subject:
                    raise OpenIDIdentityConflictError(
                        "The username is bound to an OIDC identity and cannot "
                        "be used by an unverified OAuth identity"
                    )
                if stored_issuer != issuer or stored_subject != subject:
                    raise OpenIDIdentityConflictError(
                        "The username is already bound to another OIDC identity"
                    )
            elif legacy_subject is not None:
                if not isinstance(legacy_subject, str) or not legacy_subject:
                    raise OpenIDIdentityConflictError(
                        "The username has invalid legacy OIDC identity metadata"
                    )
                if not issuer or not subject:
                    raise OpenIDIdentityConflictError(
                        "The username is bound to an OIDC identity and cannot "
                        "be used by an unverified OAuth identity"
                    )
                if legacy_subject != subject:
                    raise OpenIDIdentityConflictError(
                        "The username is already bound to another OIDC subject"
                    )

            # Defer all credential mutation until Home Assistant has resolved
            # and linked the user. AuthStore owns persisted object mutation.
            credentials.is_new = False
            return credentials

        return self.async_create_credentials(credential_data)

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return metadata for new users created from credentials."""
        name = credentials.data.get("name") or credentials.data.get("username")
        return UserMeta(name=name, is_active=True, group=GROUP_ID_USER)


async def async_register_auth_provider(hass: HomeAssistant) -> OpenIDAuthProvider:
    """Ensure the OpenID auth provider is registered with Home Assistant."""
    provider = hass.auth.get_auth_provider(DOMAIN, None)
    if isinstance(provider, OpenIDAuthProvider):
        return provider

    config: dict[str, Any] = {"type": DOMAIN}
    store: AuthStore = hass.auth._store  # noqa: SLF001
    provider = OpenIDAuthProvider(hass, store, config)
    await provider.async_initialize()
    hass.auth._providers[(DOMAIN, None)] = provider  # noqa: SLF001
    return provider
