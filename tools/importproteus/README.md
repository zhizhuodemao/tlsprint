# importproteus — registry data regeneration tool

`importproteus` converts a JSON export of the reference "proteus" preset
collection (the curl_cffi / curl-impersonate `tls_config` lineage used by the
reference projects this library was built against) into tlsprint's canonical
registry data file.

## Usage

```sh
go run ./tools/importproteus \
  -in /path/to/proteus_dump.json \
  -allow preset/data/ALLOWLIST.txt \
  -out preset/data/registry.json \
  -v
```

- `-in`: the export dump, produced by step 1 below.
- `-allow`: selection file, one `TLS_*` name per line; optional trailing
  columns override derived metadata: `NAME [product [platform [version]]]`.
- `-out`: destination JSON (defaults are fine when run from the repo root).
- `-v`: per-preset report on stderr.

The tool validates every converted preset (including registry uniqueness)
before writing anything.

## Step 1 — producing the export dump

The reference collection ships preset variables as plain Go data structs
(e.g. `TLS_CHROME_141 = Config{...}` in its `impersonate` package). To export
them without making the reference module a dependency of tlsprint, run a tiny
exporter against a **local checkout** of the reference project:

1. Copy/clone the reference repository to a scratch directory and add a local
   `replace` for its private uTLS-fork module pointing at your local checkout
   of that fork (both are usually already on disk next to each other).
2. Generate an exporter file that enumerates every `TLS_*` variable
   (variables are pure data literals — the file is a `switch` over the
   variable names), plus a small `main` that JSON-encodes each config with an
   added `"__name"` key.
3. `go run ./cmd/export names.txt > proteus_dump.json`

The resulting file is an array of objects, one per preset:

```json
[
  {
    "__name": "TLS_CHROME_141",
    "ID": "…", "JA3": "…", "CipherSuites": "…", "ExtensionOrder": "…",
    "Curves": "…", "SigAlgs": "…",
    "H2Settings": { "1": 65536, … },
    "H2SettingsOrder": ["HEADER_TABLE_SIZE", …],
    "Headers": { "User-Agent": "…" },
    …
  }
]
```

Keep the export out of the repository (it carries third-party data); commit
only the regenerated `preset/data/registry.json` plus your allowlist change.

## Conversion notes

- The dump's JA3 string is the authoritative base for version / ciphers /
  extension order / groups / ec-point-formats; the dedicated `Curves` field
  is sometimes abbreviated and is only used to record GREASE position.
- GREASE tokens ("GREASE") in group/version lists become `iana.GreaseMarker`.
- HTTP/2 settings order is preserved from `H2SettingsOrder`; the curl_cffi
  pseudo-header letter code ("masp") is expanded to header names.
- Header values keep their canonical casing; header order entries stay in
  lower-case wire form.
