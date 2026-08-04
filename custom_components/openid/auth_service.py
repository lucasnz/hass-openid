"""Provider exchange and identity validation services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant

from .const import (
    CONF_ID_TOKEN_SIGNING_ALGORITHMS,
    CONF_ISSUER,
    CONF_JWKS_URL,
    CONF_SCOPE,
    CONF_TOKEN_URL,
    CONF_USE_HEADER_AUTH,
    CONF_USER_INFO_URL,
    CONF_USERNAME_FIELD,
    CONF_VALIDATE_TLS,
    CRED_ISSUER,
    CRED_SESSION_ID,
    CRED_SUBJECT,
)
from .identity import normalize_username
from .oauth_helper import exchange_code_for_token, fetch_user_info
from .oidc_helper import async_validate_id_token


class ProviderAuthenticationError(RuntimeError):
    """Raised for an expected provider or identity validation failure."""

    def __init__(self, public_message: str, *, reason: str) -> None:
        super().__init__(reason)
        self.public_message = public_message


@dataclass(slots=True)
class ValidatedProviderIdentity:
    """Validated data returned by an identity provider."""

    username: str
    token_data: dict[str, Any]
    user_info: dict[str, Any]
    credential_fields: dict[str, Any]


async def async_exchange_and_validate_identity(
    hass: HomeAssistant,
    *,
    config: Mapping[str, Any],
    code: str,
    redirect_uri: str,
    nonce: str | None,
    code_verifier: str | None,
) -> ValidatedProviderIdentity:
    """Exchange a provider code and return a validated identity."""
    try:
        token_data = await exchange_code_for_token(
            hass=hass,
            token_url=config[CONF_TOKEN_URL],
            code=code,
            client_id=config[CONF_CLIENT_ID],
            client_secret=config[CONF_CLIENT_SECRET],
            redirect_uri=redirect_uri,
            validate_tls=bool(config.get(CONF_VALIDATE_TLS, True)),
            use_header_auth=bool(config.get(CONF_USE_HEADER_AUTH, True)),
            code_verifier=code_verifier,
        )

        id_token_claims: dict[str, Any] | None = None
        if "openid" in config.get(CONF_SCOPE, "").split():
            id_token = token_data.get("id_token")
            issuer = config.get(CONF_ISSUER)
            jwks_url = config.get(CONF_JWKS_URL)
            algorithms = config.get(CONF_ID_TOKEN_SIGNING_ALGORITHMS, ["RS256"])
            if isinstance(algorithms, str):
                algorithms = [algorithms]
            if not all(
                isinstance(value, str) and value
                for value in (id_token, nonce, issuer, jwks_url)
            ):
                raise ValueError("OIDC validation metadata or ID token is missing")
            id_token_claims = await async_validate_id_token(
                hass,
                id_token=id_token,
                issuer=issuer,
                jwks_url=jwks_url,
                client_id=config[CONF_CLIENT_ID],
                nonce=nonce,
                algorithms=list(algorithms),
                validate_tls=bool(config.get(CONF_VALIDATE_TLS, True)),
            )

        access_token = token_data.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ValueError("Token response is missing an access token")
        user_info = await fetch_user_info(
            hass=hass,
            user_info_url=config[CONF_USER_INFO_URL],
            access_token=access_token,
            validate_tls=bool(config.get(CONF_VALIDATE_TLS, True)),
        )

        if id_token_claims is not None:
            userinfo_sub = user_info.get("sub")
            if (
                not isinstance(userinfo_sub, str)
                or userinfo_sub != id_token_claims.get("sub")
            ):
                raise ValueError(
                    "UserInfo subject does not match the validated ID token"
                )

        username_field = config[CONF_USERNAME_FIELD]
        username = normalize_username(user_info.get(username_field))
        if username_field == "email" and user_info.get("email_verified") is False:
            raise ValueError("The provider has not verified the email address")

        credential_fields = {
            key: value
            for key, value in (
                ("username", username),
                ("name", user_info.get("name") or user_info.get("preferred_username")),
                ("email", user_info.get("email")),
                ("preferred_username", user_info.get("preferred_username")),
            )
            if value
        }
        if id_token_claims is not None:
            credential_fields[CRED_ISSUER] = id_token_claims["iss"]
            credential_fields[CRED_SUBJECT] = id_token_claims["sub"]
            if isinstance(id_token_claims.get("sid"), str):
                credential_fields[CRED_SESSION_ID] = id_token_claims["sid"]

        return ValidatedProviderIdentity(
            username=username,
            token_data=token_data,
            user_info=user_info,
            credential_fields=credential_fields,
        )
    except ProviderAuthenticationError:
        raise
    except Exception as err:
        raise ProviderAuthenticationError(
            "OpenID login failed! The provider response could not be validated.",
            reason=str(err),
        ) from err
