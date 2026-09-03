package tlsprint

// This file defines the semantic fingerprint model of the library.
//
// A Profile describes what a TLS client puts on the wire, at the level of
// ordered identifier lists — the level that fingerprinting services
// (tls.peet.ws, JA3/JA4 tooling) and impersonation engines (uTLS and friends)
// work with. Nothing here dials a connection and nothing depends on any TLS
// engine: profiles are plain data with JSON round-tripping, so they can be
// embedded, shipped as files, or exchanged between programs.
//
// GREASE representation
//
// The ecosystem reports two different views of GREASE:
//
//   - Real traffic carries randomized GREASE values in dedicated positions
//     (a GREASE cipher suite, a GREASE extension, a GREASE named group, ...).
//   - JA3-style canonical strings computed by fingerprint services usually
//     *omit* GREASE entries, so "4865-4866-…" not "0a0a-4865-…".
//
// tlsprint keeps both explicit and honest about it:
//
//   - Ordered lists that the source data records with GREASE positions
//     (supported_groups, supported_versions) store iana.GreaseMarker (0x0a0a)
//     at exactly those positions.
//   - Lists that are conventionally reported GREASE-free (cipher_suites,
//     extensions) keep the reported order as-is.
//   - Codecs that produce canonical strings (ja3, ja4) follow their spec and
//     strip GREASE entries; the utls adapter expands markers into concrete
//     randomized GREASE values when building a ClientHello, and payload lists
//     are routed through its randomized-GREASE handling.

// Profile is a complete, engine-independent client fingerprint: the TLS
// ClientHello fingerprint plus optional HTTP/2 and HTTP header fingerprints.
// The zero value is a valid, empty profile (all lists optional).
type Profile struct {
	// TLS is the ClientHello-level fingerprint. It is always present.
	TLS TLSProfile `json:"tls"`

	// HTTP2 describes the HTTP/2 fingerprint (SETTINGS order and values,
	// window updates, priority semantics, pseudo-header order). Nil when the
	// profile does not describe HTTP/2 behaviour.
	HTTP2 *HTTP2Profile `json:"http2,omitempty"`

	// Headers describes the HTTP header fingerprint (header order and
	// default values such as User-Agent). Nil when not described.
	Headers *HeaderProfile `json:"headers,omitempty"`
}

// TLSProfile captures the ClientHello fingerprint as ordered identifier lists.
// All fields are optional; nil/empty means "not described by this profile".
// A valid ClientHello normally needs at least CipherSuites and Extensions,
// but the model deliberately allows partial profiles (e.g. parsed JA3).
type TLSProfile struct {
	// LegacyVersion is the ClientHello legacy version (RFC 8446 §4.1.2).
	// 0 means "unset/unknown"; virtually every modern client sends 0x0303.
	LegacyVersion uint16 `json:"legacy_version,omitempty"`

	// CipherSuites is the ordered list of offered cipher suites, exactly as
	// reported by the source (conventionally GREASE-free).
	CipherSuites []uint16 `json:"cipher_suites,omitempty"`

	// Extensions is the ordered list of extension type IDs in the ClientHello
	// (conventionally GREASE-free). Extension bodies are described by the
	// dedicated fields below; the list carries the *order*, including
	// extensions without dedicated fields (they are rebuilt by the client).
	Extensions []uint16 `json:"extensions,omitempty"`

	// SupportedGroups is the ordered named-group list (supported_groups
	// extension payload). May contain iana.GreaseMarker entries.
	SupportedGroups []uint16 `json:"supported_groups,omitempty"`

	// ECFormats is the ec_point_formats payload (typically []byte{0}).
	ECFormats []uint8 `json:"ec_point_formats,omitempty"`

	// SupportedVersions is the ordered TLS version list (supported_versions
	// extension payload). May contain iana.GreaseMarker entries.
	SupportedVersions []uint16 `json:"supported_versions,omitempty"`

	// SignatureAlgorithms is the ordered signature algorithm list of the
	// signature_algorithms extension.
	SignatureAlgorithms []uint16 `json:"signature_algorithms,omitempty"`

	// SignatureAlgorithmsCert is the ordered list of the
	// signature_algorithms_cert extension, when present.
	SignatureAlgorithmsCert []uint16 `json:"signature_algorithms_cert,omitempty"`

	// PSKKeyExchangeModes is the psk_key_exchange_modes payload
	// (0 = psk_ke, 1 = psk_dhe_ke).
	PSKKeyExchangeModes []uint8 `json:"psk_key_exchange_modes,omitempty"`

	// CertCompression is the ordered algorithm list of the
	// compress_certificate extension (1 = zlib, 2 = brotli, 3 = zstd).
	CertCompression []uint16 `json:"cert_compression,omitempty"`

	// DelegatedCredentials is the ordered algorithm list of the
	// delegated_credentials extension, when present.
	DelegatedCredentials []uint16 `json:"delegated_credentials,omitempty"`

	// RecordSizeLimit is the record_size_limit extension value
	// (0 = absent).
	RecordSizeLimit uint16 `json:"record_size_limit,omitempty"`

	// RandomGrease mirrors the "random JA3" behaviour of source engines:
	// the fingerprint is derived from a GREASE-randomized base and every
	// connection may legitimately land on a slightly different JA3.
	// Informational; the utls adapter randomizes GREASE per connection and
	// ignores this flag.
	RandomGrease bool `json:"random_grease,omitempty"`

	// DisableGrease tells engines that this profile must not inject GREASE.
	DisableGrease bool `json:"disable_grease,omitempty"`

	// ExtraExtensions carries raw payloads for extension types that the
	// semantic model does not decode but that a specific client sends with a
	// fixed body (e.g. Chrome's 0xCA34). Keyed by extension type id, value is
	// the raw extension body. Used by engines to reproduce the extension
	// byte-for-byte; types without a payload here are omitted on the wire.
	ExtraExtensions map[uint16][]byte `json:"extra_extensions,omitempty"`

	// JA3 is the canonical JA3 string of the source capture, when known.
	// It is informational provenance and is verified by the preset tests.
	JA3 string `json:"ja3,omitempty"`
}

// HTTP2Profile describes the HTTP/2 fingerprint of a client.
type HTTP2Profile struct {
	// Settings is the ordered SETTINGS frame parameter list (wire order).
	Settings []HTTP2Setting `json:"settings,omitempty"`

	// SettingsAck mirrors whether the client acknowledges SETTINGS.
	// Informational: the client transport does not currently reproduce this
	// flag on the wire.
	SettingsAck bool `json:"settings_ack,omitempty"`

	// WindowUpdate is the connection flow-control window announced after
	// the SETTINGS frame.
	WindowUpdate uint32 `json:"window_update,omitempty"`

	// HeadersStreamID is the stream id used for the first HEADERS frame.
	// Informational: the client transport always uses stream 1 for the first
	// request.
	HeadersStreamID uint32 `json:"headers_stream_id,omitempty"`

	// PseudoHeaderOrder is the order of HTTP/2 pseudo headers in HEADERS
	// frames, e.g. []string{":method", ":authority", ":scheme", ":path"}.
	PseudoHeaderOrder []string `json:"pseudo_header_order,omitempty"`

	// HeaderPriority describes the priority of the first HEADERS frame.
	HeaderPriority *H2Priority `json:"header_priority,omitempty"`

	// PriorityFrames lists explicit PRIORITY frames sent after connection
	// setup.
	PriorityFrames []H2PriorityFrame `json:"priority_frames,omitempty"`
}

// HTTP2Setting is one SETTINGS parameter: a protocol identifier and value.
type HTTP2Setting struct {
	// ID is the SETTINGS parameter identifier (see iana.HTTP2SettingName).
	ID uint16 `json:"id"`
	// Value is the parameter value.
	Value uint32 `json:"value"`
}

// H2Priority describes one HTTP/2 stream priority.
type H2Priority struct {
	StreamDep uint32 `json:"stream_dep"`
	Exclusive bool   `json:"exclusive"`
	Weight    uint8  `json:"weight"`
}

// H2PriorityFrame is an explicit HTTP/2 PRIORITY frame.
type H2PriorityFrame struct {
	StreamID uint32     `json:"stream_id"`
	Priority H2Priority `json:"priority"`
}

// HeaderProfile describes the HTTP header fingerprint: which headers the
// client sends, in which order, and with which default values.
type HeaderProfile struct {
	// Order lists header names in send order (lower-case canonical form,
	// e.g. "user-agent").
	Order []string `json:"order,omitempty"`

	// Values holds default header values keyed by canonical header name.
	Values map[string]string `json:"values,omitempty"`
}

// UserAgent returns the User-Agent default value, if any.
func (h *HeaderProfile) UserAgent() string {
	if h == nil {
		return ""
	}
	// Accept both canonical ("User-Agent") and wire ("user-agent") keys.
	if v, ok := h.Values["user-agent"]; ok {
		return v
	}
	return h.Values["User-Agent"]
}
