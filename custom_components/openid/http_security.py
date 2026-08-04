"""Security helpers for authentication-related HTTP responses."""

from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
import json
from typing import Any

from aiohttp.web import Response

NO_STORE_HEADERS: dict[str, str] = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
}

HTML_SECURITY_HEADERS: dict[str, str] = {
    **NO_STORE_HEADERS,
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
}


def html_response(
    text: str,
    *,
    status: HTTPStatus = HTTPStatus.OK,
    headers: Mapping[str, str] | None = None,
) -> Response:
    """Return an authentication HTML response with restrictive headers."""
    response_headers = dict(HTML_SECURITY_HEADERS)
    if headers:
        response_headers.update(headers)
    return Response(
        status=status,
        text=text,
        content_type="text/html",
        charset="utf-8",
        headers=response_headers,
    )


def json_response(
    payload: Mapping[str, Any],
    *,
    status: HTTPStatus = HTTPStatus.OK,
) -> Response:
    """Return a no-store JSON response."""
    return Response(
        status=status,
        text=json.dumps(payload, separators=(",", ":")),
        content_type="application/json",
        charset="utf-8",
        headers=NO_STORE_HEADERS,
    )


def redirect_response(location: str) -> Response:
    """Return a no-store redirect response."""
    return Response(
        status=HTTPStatus.FOUND,
        headers={"Location": location, **NO_STORE_HEADERS},
    )


def text_response(
    text: str,
    *,
    status: HTTPStatus = HTTPStatus.OK,
) -> Response:
    """Return a no-store plain-text authentication response."""
    return Response(
        status=status,
        text=text,
        content_type="text/plain",
        charset="utf-8",
        headers=NO_STORE_HEADERS,
    )


def empty_response(*, status: HTTPStatus) -> Response:
    """Return an empty no-store authentication response."""
    return Response(status=status, headers=NO_STORE_HEADERS)
