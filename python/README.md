# tlsprint-python

Python HTTP client backed by the existing [tlsprint](https://github.com/lingulingo/tlsprint)
Go engine: uTLS, its customized HTTP/2 transport, and all 47 built-in fingerprint
presets across 13 products. The distribution name is **tlsprint-python**; import
it as **tlsprint**. The unrelated PyPI package named `tlsprint` must not be
installed in the same environment.

```sh
pip install tlsprint-python
```

Python 3.10 or newer is required. A compatible wheel contains the native engine
and requires neither Go nor a C compiler at runtime. Platforms without a
compatible wheel build from the source distribution and need Go >= 1.24 and a C
compiler. There are no Python runtime dependencies.

The 0.1.1 wheel matrix covers these 64-bit platforms:

| Operating system | Architectures | Minimum runtime |
| --- | --- | --- |
| Linux (glibc) | x86_64, ARM64/aarch64 | glibc 2.17 (`manylinux2014`) |
| Linux (Alpine/musl) | x86_64, ARM64/aarch64 | musl 1.2 (`musllinux_1_2`) |
| macOS | Intel x86_64, Apple Silicon ARM64 | macOS 11 |
| Windows | x64/AMD64, ARM64 | Windows 10 x64 / Windows 11 ARM64 |

Each wheel is built and integration-tested on its OS and architecture, including
requests made with Go and the C compiler removed from PATH. Tests cover Python
3.10 and 3.14 (3.11 and 3.14 for Windows ARM64). 32-bit systems are not in this
release matrix. Use `pip install --only-binary=:all: tlsprint-python` to require
a prebuilt wheel and avoid an automatic source build.

```python
import tlsprint

print([p["key"] for p in tlsprint.list_presets(product="chrome")])
print(tlsprint.get_preset("chrome-142")["version"])

with tlsprint.Session(impersonate="chrome-142", timeout=30) as session:
    response = session.get("https://example.com", params={"q": "hello"})
    response.raise_for_status()
    print(response.status_code, response.http_version, response.text)

    response = session.post("https://httpbin.org/post", json={"hello": "world"})
    print(response.json())

# Convenience calls create and close a session for each request.
response = tlsprint.get("https://example.com", impersonate="firefox-145")
```

## API

`Session(impersonate="chrome", headers=None, timeout=30, proxy=None,
verify=True, http_version="auto", allow_redirects=True, cookies=True)`

- Presets accept exact keys and the Go registry's aliases, including `chrome`,
  `chrome-142`, `firefox-145`, and `safari-26.0.1`. Full keys select an unambiguous
  capture when several presets share a version. Product aliases select the
  newest **bundled** preset, not the newest browser available online.
- `get`, `post`, `put`, `patch`, `delete`, `head`, `options`, and
  `request(method, url)` accept `params`, `headers`, `data`, `json`, and `timeout`.
  `data` accepts bytes (including NUL bytes), strings, mappings, or form pairs.
  `json=None` explicitly sends JSON `null`. `data` and `json` are exclusive.
- Timeouts are seconds for the whole request. `None` disables the deadline.
  Each request can override the session default, including with a longer value.
- `verify=True` uses system trust; a PEM CA path replaces the trust pool.
  `verify=False` disables target certificate verification.
- `proxy` accepts HTTP or HTTPS proxy URLs, including basic credentials. HTTPS
  targets use CONNECT so their TLS handshake still comes from the preset.
  HTTPS proxy certificates use system trust independently of target `verify`.
  Environment proxy variables are not read. SOCKS proxies are not supported.
- `http_version` is `auto`, `h1`, or `h2`. Auto attempts HTTP/2 with the core's
  HTTP/1.1 fallback. Plain HTTP uses HTTP/1.1. Presets without H2 support also use
  HTTP/1.1; `h2` does not add capabilities to those presets.
- Cookies persist in the Go session jar by default. `allow_redirects` and
  `cookies` configure the session at construction. The core's redirect limit
  applies. Session headers may be changed between requests.
- Responses expose `status_code`, `status`, `url`, `http_version`, `headers`,
  `content`, `text`, `encoding`, `elapsed` (a `timedelta`), `ok`, `json()`, and
  `raise_for_status()`. Headers are case-insensitive;
  `headers.get_list("set-cookie")` preserves repeated values.
- `Timeout`, `SSLError`, `ConnectionError`, `Cancelled`, `SessionClosed`,
  `InvalidArgument`, and `HTTPError` are available directly from `tlsprint`.
  `HTTPError.response` contains the response.

## Scope and lifetime

The TLS engine, transport, connection pool, cookie jar and preset registry stay
in Go. Python handles the public interface, argument encoding and response
objects. The private C ABI exchanges JSON metadata and raw body buffers;
Python always frees returned native allocations. Session handles are integer
IDs, not exposed Go pointers. Calls release the Python GIL while Go runs.

A session supports concurrent requests. Configuration affecting the transport
is fixed for its lifetime; create a new session to change presets or proxies.
Do not mutate `session.headers` or `session.timeout` concurrently with requests.
Use a context manager or `close()` to cancel active requests and release pooled
connections. Use multiprocessing's `spawn` method; using the embedded Go runtime
after `fork` is unsupported and rejected.

This version is synchronous and buffers the whole body. It does not implement
streaming, async, multipart uploads, WebSockets or HTTP/3. Large responses consume
memory in both runtimes. Bodies are automatically decompressed by the Go client;
response headers still describe the original encoded response. The core falls
back to raw bytes for unsupported or malformed compression.

Fingerprint behavior is inherited from tlsprint, not a complete browser runtime.
GREASE and cryptographic randomness vary, and fresh connections omit resumption
extensions. HTTP/2 settings and ordering follow the selected preset; HTTP/1.1
header ordering is controlled by Go's standard transport. A preset's browser
version label does not promise identical behavior to every feature of that browser.

## Build and verify

From this directory, with Go and a C compiler installed:

```sh
uv build
uv venv .venv
uv pip install --python .venv/bin/python dist/*.whl
cd native
go build -o ../build/testserver ./testserver
go test -race ./...
cd ..
TLSPRINT_TEST_SERVER="$PWD/build/testserver" .venv/bin/python -m unittest discover -s tests -v
```

The source distribution contains a frozen copy of the necessary Go sources and
embedded preset data, with module checksums; it builds independently of the
original checkout. Building may download the pinned Go dependencies. Wheels are
platform-specific but independent of CPython's extension ABI (`py3-none-<platform>`).
Third-party license texts are included in `licenses/`.

The [Python wheel workflow](https://github.com/zhizhuodemao/tlsprint/actions/workflows/python-wheels.yml)
builds with cibuildwheel. Linux builds run inside manylinux/musllinux containers;
Windows uses a checksum-verified LLVM-MinGW toolchain. auditwheel, delocate and
delvewheel check platform dependencies before installation tests run. The workflow
uploads tested artifacts to GitHub; it does not hold PyPI credentials.

To run a native platform build locally from the repository root:

```sh
python -m pip install cibuildwheel==4.2.1
python -m cibuildwheel python --output-dir wheelhouse
```

Linux requires Docker. macOS requires Go and Xcode command-line tools. Windows
requires Go and a working MinGW-w64 C compiler selected by `CC`. The workflow
provides those toolchains on its native runners.

Publishing reviewed artifacts to production PyPI, after configuring `uv auth`
or supplying a token securely through the environment:

```sh
uv publish --username __token__ --trusted-publishing never dist/*
```
