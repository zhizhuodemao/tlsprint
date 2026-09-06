"""Errors raised by the Python API and the native transport."""


class TLSError(Exception):
    """Base exception for tlsprint."""


class InvalidArgument(TLSError, ValueError):
    pass


class RequestError(TLSError):
    pass


class ConnectionError(RequestError):
    pass


class SSLError(ConnectionError):
    pass


class Timeout(RequestError):
    pass


class Cancelled(RequestError):
    pass


class SessionClosed(TLSError):
    pass


class HTTPError(RequestError):
    def __init__(self, response):
        self.response = response
        super().__init__(f"{response.status} for {response.url}")
