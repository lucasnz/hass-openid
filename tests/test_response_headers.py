"""Tests for security headers on authentication responses."""

from custom_components.openid.http_security import html_response, json_response


def test_sensitive_responses_are_not_cacheable() -> None:
    """HTML and JSON authentication responses explicitly disable caching."""
    for response in (html_response("ok"), json_response({"ok": True})):
        assert "no-store" in response.headers["Cache-Control"]
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
