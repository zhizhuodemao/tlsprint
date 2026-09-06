"""Private, versioned C ABI. Every native result has exactly one owner."""

import ctypes
import json
import os
from pathlib import Path
import sys
import threading

from . import exceptions


class _Result(ctypes.Structure):
    _fields_ = [
        ("metadata", ctypes.c_void_p),
        ("metadata_len", ctypes.c_size_t),
        ("body", ctypes.c_void_p),
        ("body_len", ctypes.c_size_t),
    ]


_library = None
_pid = os.getpid()
_lock = threading.Lock()
_errors = {
    name: getattr(exceptions, name)
    for name in (
        "InvalidArgument",
        "RequestError",
        "ConnectionError",
        "SSLError",
        "Timeout",
        "Cancelled",
        "SessionClosed",
    )
}


def _load():
    global _library
    # A Go runtime cannot safely resume in a forked child. Check before locks.
    if os.getpid() != _pid:
        raise exceptions.TLSError(
            "Use multiprocessing with the 'spawn' start method; tlsprint cannot run after fork"
        )
    with _lock:
        if _library is None:
            suffix = (
                ".dll"
                if sys.platform == "win32"
                else ".dylib"
                if sys.platform == "darwin"
                else ".so"
            )
            path = Path(__file__).with_name("_libtlsprint" + suffix)
            try:
                lib = ctypes.CDLL(str(path))
            except OSError as exc:
                raise ImportError(
                    "tlsprint's native library is unavailable. Install a compatible "
                    "tlsprint-python wheel, or build the package with Go >= 1.24 and a C compiler."
                ) from exc
            lib.tlsprint_abi_version.argtypes = []
            lib.tlsprint_abi_version.restype = ctypes.c_uint32
            if lib.tlsprint_abi_version() != 1:
                raise ImportError("Unsupported tlsprint native ABI version")
            lib.tlsprint_call.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_void_p,
                ctypes.c_size_t,
            ]
            lib.tlsprint_call.restype = ctypes.POINTER(_Result)
            lib.tlsprint_free.argtypes = [ctypes.POINTER(_Result)]
            lib.tlsprint_free.restype = None
            _library = lib
        return _library


def call(command, body=b""):
    lib = _load()
    metadata = json.dumps(command, ensure_ascii=True, allow_nan=False).encode("utf-8")
    if len(body) > 2**31 - 1:
        raise exceptions.InvalidArgument(
            "request body exceeds the native ABI's 2 GiB limit"
        )
    result = lib.tlsprint_call(metadata, len(metadata), body, len(body))
    if not result:
        raise MemoryError("native result allocation failed")
    try:
        value = result.contents
        meta = json.loads(ctypes.string_at(value.metadata, value.metadata_len))
        if isinstance(meta, dict) and "error" in meta:
            error = meta["error"]
            raise _errors.get(error["type"], exceptions.RequestError)(error["message"])
        payload = (
            ctypes.string_at(value.body, value.body_len) if value.body_len else b""
        )
        return meta, payload
    finally:
        lib.tlsprint_free(result)
