// Package tlsprint is an engine-independent library for describing,
// parsing, computing, and validating TLS client fingerprints.
//
// It is the "standard data layer" that higher-level clients (browser
// impersonation HTTP clients, TLS fingerprint identification tools, WAF
// research harnesses) build on. It does not dial connections itself and has
// zero third-party dependencies; dialing engines such as uTLS can consume its
// profiles through the optional adapter in the utls submodule
// (github.com/lingulingo/tlsprint/utls).
//
// The library is organised into layers:
//
//   - tlsprint (root): the semantic fingerprint model — ordered identifier
//     lists for the TLS ClientHello plus optional HTTP/2 and HTTP header
//     fingerprints, with JSON round-tripping and validation.
//   - tlsprint/iana: identifier registries (extensions, cipher suites,
//     named groups, signature algorithms, versions, HTTP/2 settings) with
//     name↔id helpers and GREASE semantics.
//   - tlsprint/hello: wire-level ClientHello parsing and construction.
//   - tlsprint/ja3 and tlsprint/ja4: canonical fingerprint string codecs.
//   - tlsprint/preset: curated, versioned fingerprints of real browsers and
//     other TLS clients (the "fingerprint database"), loadable by name.
//   - cmd/tlsprint: a command-line tool for inspecting profiles and
//     computing fingerprints.
//
// Data model philosophy: profiles describe what a client actually puts on the
// wire. GREASE placeholders are recorded explicitly (iana.GreaseMarker) only
// where the source data records their position (e.g. supported_groups /
// supported_versions); JA3-style derived lists keep the ecosystem convention
// of reporting GREASE-free identifier lists. See the package documentation in
// profile.go for details and the README for examples.
package tlsprint
