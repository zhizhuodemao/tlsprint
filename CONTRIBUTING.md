# Contributing to tlsprint

Thanks for helping make tlsprint better! This project aims to be a standard,
open, dependency-light TLS fingerprint library, and contributions are
welcome in every form: bug reports, documentation, new profiles, codec fixes
and feature proposals.

## Ground rules

- The root module stays **stdlib-only**. Engine integrations (uTLS, QUIC, ...)
  belong in their own submodule.
- Presets are **data with provenance**, not code. New fingerprints should
  come from captured traffic, be traceable to their source, and satisfy the
  registry invariants (see `preset/preset_test.go`): a profile must re-derive
  the JA3 of its capture.
- Codecs follow the public specifications (JA3 ecosystem conventions, the
  FoxIO JA4 spec, RFC 8446). Specification changes land with their test
  vectors.
- Behavioural changes need tests; golden vectors are preferred.

## Development workflow

```sh
make test        # core module tests
make vet         # go vet
make test-utls   # optional uTLS submodule tests
```

Before submitting:

1. `gofmt -l .` is clean.
2. `go vet ./...` is clean.
3. `go test ./...` passes.
4. If you changed the uTLS adapter, `cd utls && go test ./...` passes too.

## Updating the preset registry

See `preset/data/README.md`. In short: export the reference preset variables
to a JSON dump, add the new names to `preset/data/ALLOWLIST.txt`, and run the
import tool; commit the regenerated `registry.json` and the allowlist change
together.

## Pull requests

- Open an issue first for non-trivial changes so work isn't duplicated.
- Keep PRs focused; one logical change per PR.
- Write commit messages in imperative mood.

## Reporting security issues

Do **not** open a public issue for vulnerabilities. Follow
[SECURITY.md](SECURITY.md).

## Code of conduct

Be respectful and constructive. This is a small, technical project — assume
good faith.
