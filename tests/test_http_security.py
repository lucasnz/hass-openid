"""Tests for browser-bound transactions and output encoding."""

from types import SimpleNamespace

from aiohttp.test_utils import make_mocked_request

from custom_components.openid.const import DOMAIN
from custom_components.openid.views import _android_waiting_response


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
    cookie = response.headers.getall("Set-Cookie")[0]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
