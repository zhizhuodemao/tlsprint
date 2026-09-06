from collections.abc import Mapping
from datetime import timedelta
from email.message import Message
import json

from .exceptions import HTTPError


class Headers(Mapping):
    """Case-insensitive response headers; get_list preserves repeated values."""

    def __init__(self, values):
        self._values = {
            key.lower(): (key, tuple(items)) for key, items in values.items()
        }

    def __getitem__(self, key):
        return ", ".join(self._values[key.lower()][1])

    def __iter__(self):
        return (key for key, _ in self._values.values())

    def __len__(self):
        return len(self._values)

    def get_list(self, key):
        value = self._values.get(key.lower())
        return list(value[1]) if value else []


class Response:
    """A fully buffered response. content is decompressed by the Go engine."""

    def __init__(self, metadata, content):
        self.status_code = metadata["status_code"]
        self.status = metadata["status"]
        self.headers = Headers(metadata["headers"])
        self.url = metadata["url"]
        self.http_version = metadata["http_version"]
        self.elapsed = timedelta(seconds=metadata["elapsed"])
        self.content = content
        message = Message()
        message["content-type"] = self.headers.get("content-type", "")
        self.encoding = message.get_content_charset() or "utf-8"

    @property
    def text(self):
        return self.content.decode(self.encoding, errors="replace")

    @property
    def ok(self):
        return self.status_code < 400

    def json(self, **kwargs):
        return json.loads(self.content, **kwargs)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise HTTPError(self)

    def __repr__(self):
        return f"<Response [{self.status_code}]>"
