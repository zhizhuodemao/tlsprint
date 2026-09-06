"""Python interface to tlsprint's Go TLS and HTTP/2 fingerprint engine."""

from . import _native
from .exceptions import (
    Cancelled,
    ConnectionError,
    HTTPError,
    InvalidArgument,
    RequestError,
    SessionClosed,
    SSLError,
    TLSError,
    Timeout,
)
from .response import Headers, Response
from .session import Session

__version__ = "0.1.1"
__all__ = [
    "Session",
    "Response",
    "Headers",
    "list_presets",
    "get_preset",
    "request",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "TLSError",
    "InvalidArgument",
    "RequestError",
    "ConnectionError",
    "SSLError",
    "Timeout",
    "Cancelled",
    "SessionClosed",
    "HTTPError",
]


def list_presets(product=None):
    """Return full preset dictionaries, optionally filtered by product."""
    if product is not None and not isinstance(product, str):
        raise InvalidArgument("product must be a string or None")
    return _native.call({"op": "list_presets", "product": product or ""})[0]


def get_preset(name):
    """Resolve a full key or alias such as chrome-142 using the Go registry."""
    if not isinstance(name, str):
        raise InvalidArgument("name must be a string")
    return _native.call({"op": "get_preset", "name": name})[0]


def request(
    method,
    url,
    *,
    impersonate="chrome",
    proxy=None,
    verify=True,
    http_version="auto",
    allow_redirects=True,
    **kwargs,
):
    """Make one request with a short-lived session. Use Session for pooling."""
    with Session(
        impersonate=impersonate,
        proxy=proxy,
        verify=verify,
        http_version=http_version,
        allow_redirects=allow_redirects,
    ) as session:
        return session.request(method, url, **kwargs)


def get(url, **kwargs):
    return request("GET", url, **kwargs)


def post(url, **kwargs):
    return request("POST", url, **kwargs)


def put(url, **kwargs):
    return request("PUT", url, **kwargs)


def patch(url, **kwargs):
    return request("PATCH", url, **kwargs)


def delete(url, **kwargs):
    return request("DELETE", url, **kwargs)


def head(url, **kwargs):
    return request("HEAD", url, **kwargs)


def options(url, **kwargs):
    return request("OPTIONS", url, **kwargs)
