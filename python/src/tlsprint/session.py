from collections.abc import Mapping
import json as jsonlib
import math
import os
import threading
from urllib.parse import urlencode, urlsplit, urlunsplit
import weakref

from . import _native
from .exceptions import InvalidArgument, SessionClosed
from .response import Response

_DEFAULT = object()


def _timeout(value):
    if value is None:
        return 0
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 < value < 9223372036
    ):
        raise InvalidArgument(
            "timeout must be a positive number of seconds, or None to disable it"
        )
    return value


def _headers(values):
    result = {}
    if values is not None:
        if not isinstance(values, Mapping):
            raise InvalidArgument("headers must be a mapping of strings to strings")
        for key, value in values.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise InvalidArgument("header names and values must be strings")
            # Lowercase before merging so per-request overrides ignore case.
            result[key.lower()] = value
    return result


def _close(handle):
    _native.call({"op": "close_session", "session_id": handle})


def _finalize(handle):
    try:
        _close(handle)
    except Exception:
        # Interpreter shutdown or a forked child; explicit close reports errors.
        pass


class Session:
    """Reusable synchronous client with a fixed preset and connection pool.

    timeout is in seconds and covers the whole request, including reading the
    body. None disables it. verify accepts True, False, or a PEM CA file path.
    Requests may run concurrently; close cancels and waits for active calls.
    """

    def __init__(
        self,
        *,
        impersonate="chrome",
        headers=None,
        timeout=30,
        proxy=None,
        verify=True,
        http_version="auto",
        allow_redirects=True,
        cookies=True,
    ):
        if not isinstance(impersonate, str):
            raise InvalidArgument("impersonate must be a preset name")
        if proxy is not None and not isinstance(proxy, str):
            raise InvalidArgument("proxy must be a URL string or None")
        if http_version not in {"auto", "h1", "h2"}:
            raise InvalidArgument("http_version must be auto, h1, or h2")
        if not isinstance(allow_redirects, bool) or not isinstance(cookies, bool):
            raise InvalidArgument("allow_redirects and cookies must be booleans")
        self.timeout = timeout
        _timeout(timeout)
        self.headers = _headers(headers)
        ca_file = ""
        if not isinstance(verify, bool):
            if not isinstance(verify, (str, os.PathLike)):
                raise InvalidArgument("verify must be a boolean or PEM CA file path")
            ca_file = os.fsdecode(verify)
            if not ca_file:
                raise InvalidArgument("CA file path cannot be empty")
            verify = True
        self._lock = threading.Lock()
        self._closed = False
        meta, _ = _native.call(
            {
                "op": "new_session",
                "options": {
                    "impersonate": impersonate,
                    "proxy": proxy or "",
                    "verify": verify,
                    "ca_file": ca_file,
                    "protocol": http_version,
                    "redirects": allow_redirects,
                    "cookies": cookies,
                },
            }
        )
        self._handle = meta["session_id"]
        self.impersonate = meta["preset"]
        self._finalizer = weakref.finalize(self, _finalize, self._handle)

    def request(
        self,
        method,
        url,
        *,
        params=None,
        headers=None,
        data=None,
        json=_DEFAULT,
        timeout=_DEFAULT,
    ):
        if not isinstance(method, str) or not method:
            raise InvalidArgument("method must be a non-empty string")
        if not isinstance(url, str):
            raise InvalidArgument("url must be a string")
        with self._lock:
            if self._closed:
                raise SessionClosed("session is closed")
            handle = self._handle
        if params is not None:
            parts = urlsplit(url)
            query = urlencode(params, doseq=True)
            url = urlunsplit(
                parts._replace(query="&".join(p for p in (parts.query, query) if p))
            )
        merged = _headers(self.headers)
        merged.update(_headers(headers))
        has_body = data is not None or json is not _DEFAULT
        body = b""
        if json is not _DEFAULT:
            if data is not None:
                raise InvalidArgument("data and json cannot be used together")
            body = jsonlib.dumps(
                json, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            ).encode("utf-8")
            merged.setdefault("content-type", "application/json")
        elif isinstance(data, Mapping) or isinstance(data, (list, tuple)):
            body = urlencode(data, doseq=True).encode("utf-8")
            merged.setdefault("content-type", "application/x-www-form-urlencoded")
        elif isinstance(data, str):
            body = data.encode("utf-8")
        elif isinstance(data, (bytes, bytearray, memoryview)):
            body = bytes(data)
        elif data is not None:
            raise InvalidArgument(
                "data must be bytes, a string, a mapping, or form pairs"
            )
        seconds = _timeout(self.timeout if timeout is _DEFAULT else timeout)
        meta, payload = _native.call(
            {
                "op": "request",
                "session_id": handle,
                "request": {
                    "method": method.upper(),
                    "url": url,
                    "headers": merged,
                    "timeout": seconds,
                    "has_body": has_body,
                },
            },
            body,
        )
        return Response(meta, payload)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def patch(self, url, **kwargs):
        return self.request("PATCH", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
        _close(self._handle)
        self._finalizer.detach()

    def __enter__(self):
        with self._lock:
            if self._closed:
                raise SessionClosed("session is closed")
        return self

    def __exit__(self, *args):
        self.close()
