# Security model

## Identity binding

The claim configured by `username_field` is used only to locate a Home Assistant
account during the initial link. Once linked, the OpenID credential is pinned to
the provider's stable `issuer` and `sub` claims. A later identity presenting the
same username with a different issuer or subject is rejected and requires an
explicit administrator migration.

The existing Person reassignment and first-login group behavior are retained.
Administrators should understand and test those behaviors before enabling
automatic user creation.

## OIDC and legacy OAuth

The `openid` scope is required by default. Removing it requires explicitly
enabling legacy OAuth UserInfo identity mode, which does not provide ID-token
signature, issuer, audience, or nonce validation.

## Browser and Android flows

Android polling transactions are protected by a server-generated transaction ID
and a separate high-entropy proof held in an HttpOnly, SameSite cookie. Polling
state is one-use and expires in memory. Authentication HTML uses external scripts
and restrictive no-store/content-security headers.

## Logout

Frontends receive only a short-lived, same-origin logout ticket. ID tokens remain
server-side. Providers may register the following endpoint for OIDC back-channel
logout:

`/auth/openid/backchannel_logout`

The endpoint requires a signed logout token and rejects token replay.

## Home Assistant compatibility

This integration patches private Home Assistant authentication routes because
Home Assistant does not currently expose a public extension API for this flow.
Runtime patches are installed transactionally and restored only when their target
has not been replaced by another component. CI tests both the pinned Home
Assistant test helper and the current helper release.
