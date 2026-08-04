"""Tests for browser-bound transactions and output encoding."""

from types import SimpleNamespace

from aiohttp.test_utils import make_mocked_request
import pytest

from custom_components.openid.const import DOMAIN
from custom_components.openid.views import (
    _android_poll_cookie_name,
    _android_waiting_response,
)


def test_android_poll_secret_is_cookie_bound_and_not_rendered() -> None:
    """The polling proof is HttpOnly and absent from the response body."""
    hass = SimpleNamespace(
        data={
            DOMAIN: {
                "android_waiting_template": (
                    '<body data-authorize-url="$authorize_url" '
                    'data-transaction-id="$transaction_id"></body>'
                )
            }
        }
    )
    request = make_mocked_request("GET", "https://ha.example/auth/openid/authorize")
    secret = "browser-only-secret"
    response = _android_waiting_response(
        hass,
        request,
        'https://idp.example/authorize?state="</script><script>alert(1)</script>',
        "transaction",
        secret,
    )
    assert secret not in response.text
    assert "</script><script>" not in response.text
    cookie = response.cookies[_android_poll_cookie_name("transaction")]
    assert cookie.value == secret
    assert cookie["httponly"] is True
    assert cookie["samesite"] == "Lax"


@pytest.mark.asyncio
async def test_android_transaction_cannot_be_polled_without_browser_cookie() -> None:
    """Knowing a transaction ID alone never returns an HA authorization code."""
    from custom_components.openid.state_store import (
        ANDROID_STATE_STORE,
        ANDROID_STATE_TTL,
        store_pending,
    )
    from custom_components.openid.views import OpenIDAndroidStatusView

    hass = SimpleNamespace(data={})
    store_pending(
        hass,
        ANDROID_STATE_STORE,
        "known-transaction",
        {
            "status": "completed",
            "secret_hash": "not-the-supplied-secret",
            "callback_url": "https://ha.example/?code=secret-code",
        },
        ttl=ANDROID_STATE_TTL,
    )
    request = make_mocked_request(
        "GET",
        "/auth/openid/android/status?transaction=known-transaction",
    )
    response = await OpenIDAndroidStatusView(hass).get(request)
    assert response.status == 403
    assert "secret-code" not in response.text
