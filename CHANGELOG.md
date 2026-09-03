# Changelog

All notable changes to tlsprint are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Initial open-source release.

### Added

- **Core model** (`tlsprint` root package): `Profile`, `TLSProfile`,
  `HTTP2Profile`, `HeaderProfile` with JSON round-tripping and validation.
- **Registries** (`tlsprint/iana`): name↔id tables for TLS extensions, cipher
  suites, named groups, signature algorithms, versions and HTTP/2 settings,
  plus RFC 8701 GREASE semantics (`IsGrease`, `GreaseMarker`, `NextGrease`).
- **Wire codec** (`tlsprint/hello`): byte-faithful ClientHello parse and
  construction (record / bare-handshake / bare-body auto-detection), strict
  decoders and encoders for well-known extensions, profile extraction.
- **Codecs**:
  - `tlsprint/ja3` — canonical JA3 strings and md5 hashes (GREASE-free per
    ecosystem convention), parse and format helpers.
  - `tlsprint/ja4` — JA4 fingerprints implemented against the FoxIO JA4
    specification, validated with the spec's canonical example vector
    (`t13d1516h2_8daaf6152771_e5627efa2ab1`).
- **Preset registry** (`tlsprint/preset`): 46 curated fingerprints embedded
  from `preset/data/registry.json`, lookup by exact/normalised name or by
  product, with a data-provenance statement and the JA3-re-derivation
  invariant enforced in tests.
- **uTLS adapter** (`tlsprint/utls`, separate Go module): profile → uTLS
  `ClientHelloSpec` conversion with documented GREASE/ALPN/key-share options,
  pinned against `github.com/refraction-networking/utls v1.8.2`.
- **TLS dial API** (`tlsprint/utls`): `Dial` / `DialByName` apply a preset
  fingerprint and complete a real TLS handshake (custom dialer, root pool and
  verification options included). Loopback integration tests capture the
  ClientHello actually sent and assert its canonical JA3 equals the preset's.
- **Chrome 152 preset** (`TLS_CHROME_152_MACOS_10_15_7`): added from a real
  `tls.peet.ws` capture — cipher order, groups (incl. X25519MLKEM768),
  versions, signature algorithms (with a leading GREASE), HTTP/2 settings and
  header defaults; verified end-to-end against `tls.peet.ws` (server-reported
  JA3 matches) and a real Akamai-protected site.
- **Unknown-extension raw payloads** (`tlsprint.TLSProfile.ExtraExtensions`):
  profiles can carry opaque bodies for extension types the semantic model does
  not decode (e.g. Chrome's 0xCA34), so engines can reproduce them exactly.
- **Handshake compatibility fixes** (`tlsprint/utls`), validated against a
  real Akamai-protected site:
  - GREASE markers inside payload lists (supported_groups, supported_versions)
    are now emitted as randomized GREASE values rather than literal
    placeholders, which strict servers reject as invalid identifiers.
  - Extensions that profiles list but carry no payload — SCT (18) and the
    ALPS codepoints (17513 / 17613) — are omitted instead of being marshaled
    as malformed zero-length bodies (a fatal `decode_error` on Akamai).
  - `psk_key_exchange_modes` defaults to `psk_dhe_ke` (Chrome's value) when a
    profile records the extension but not the modes.
  - ECH is emitted as Chrome's GREASE ECH (`BoringGREASEECH`) when no ECH
    configs are present.
  - ALPS (17513 / 17613), SCT (18) and post_handshake_auth (49) are now
    emitted with their correct wire forms (previously omitted); unknown
    extension types carry their raw `ExtraExtensions` payload when one exists,
    and are omitted otherwise rather than emitting a malformed empty body.
- **JA4**: GREASE values in the signature-algorithm list are now ignored, per
  the JA4 spec (Chrome prefaces sigalgs with a GREASE value).
- **HTTP/2 fingerprinting (option C)** — forked `tlsprint/http2` transport
  (based on `golang.org/x/net/http2`) with a configurable connection
  fingerprint: exact SETTINGS parameter order, the initial WINDOW_UPDATE, the
  request pseudo-header order (`m,a,s,p`), the request header order, and the
  stream priority on the HEADERS frame. The `client` applies these from the
  preset's HTTP/2/header profiles. Verified live against `tls.peet.ws`:
  the reported `akamai_fingerprint` and the HEADERS field order match the real
  Chrome 152 capture exactly.
- **Client header defaults**: `SetBrowser` now also applies the preset's
  declared header values (sec-ch-ua, accept, ...) as default request headers,
  refreshed on preset switch, unless the user set them explicitly.
- **curl_cffi-style API**: module-level `client.Get/Post/...` with the
  fingerprint passed on the call (`Impersonate("chrome-152")`) plus reusable
  session verbs and request options (`Header/Headers/Query/Cookie/Body/...`).
- **Automatic response decompression** (`client`): `Body`/`String`/`JSON` now
  decode the response based on `Content-Encoding` (gzip, deflate, br, zstd)
  transparently; `RawBody()` exposes the original compressed bytes.
- **Release-readiness fixes** (from an independent adversarial review):
  - Newest-preset resolution now compares versions numerically
    (`Lookup("curl")` correctly returns 8.16.0, not 8.9.1).
  - `Client` is genuinely safe for concurrent use: `baseURL` is snapshotted
    into each request; added `Close`/`CloseIdleConnections` and the module-level
    helpers recycle their connection pool.
  - `ja3.Compute`/`FromProfile` no longer panic on nil.
  - `TLSProfile.Validate` now enforces real structural invariants (duplicate
    ids, empty ciphers/extensions) and adds `ValidateStrict`.
  - HTTP/2 h1 fallback only retries idempotent requests with a replayable body.
  - The preset's HTTP/2 PRIORITY frames are forwarded to the wire.
  - `https://` proxies are dialed over TLS (and unknown schemes are rejected)
    instead of silently downgrading to plaintext.
  - Removed a duplicate SETTINGS field in the http2 fork; client package docs
    updated to reflect the implemented HTTP/2 fingerprinting.
- **CLI** (`cmd/tlsprint`): `list`, `show`, `fp` subcommands.
- **HTTP client** (`tlsprint/client`, separate Go module): resty/proteus-style
  `NewClient().SetBrowser(...)` + fluent `R()` builder with Get/Post/Put/Patch/
  Delete/Head, query/path params, headers, auth, JSON/form/multipart bodies,
  result decoding, cookies, redirects, CONNECT proxies and timeouts. TLS
  fingerprinting is applied per connection through the uTLS adapter; HTTP/2 is
  attempted first with automatic HTTP/1.1 fallback (`ForceHTTP1()`/`UseHTTP2()`
  to pin). Covered by loopback integration tests (h2, h1 fallback, forms,
  redirects, cookies).
- **Tooling** (`tools/importproteus`): reproducible converter from a reference
  preset export to the canonical registry data.
- **Docs**: English and Chinese README, data provenance, contribution and
  security guides, CI workflow.
