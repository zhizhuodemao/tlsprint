# Security Policy

## Scope

tlsprint parses and constructs TLS ClientHello bytes and ships fingerprint
data. Security-sensitive areas include:

- the wire parsers in `tlsprint/hello` (malformed input handling);
- profile validation and JSON decoding in the root package and `preset`;
- the data files under `preset/data` (fingerprint profiles are trusted input
  embedded at build time — treat PRs changing them like code).

The library performs no networking of its own; the optional `utls` submodule
delegates cryptography to uTLS.

## Reporting a vulnerability

Please do **not** open a public issue. Report privately by email to the
maintainers (address will be listed once the repository is published) or via
GitHub's private vulnerability reporting if enabled on the repository.

Include:

- affected versions,
- a minimal reproducer (preferably a hex dump or Go test),
- impact assessment if known.

## Response expectations

- Acknowledgment within 5 business days.
- We will coordinate disclosure with you.

## Supported versions

Only the latest release line receives security fixes. When you report a bug,
check `CHANGELOG.md` to see if a newer release already fixes it.
