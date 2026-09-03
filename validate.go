package tlsprint

import (
	"errors"
	"fmt"
	"strings"
)

// Common sentinel errors. All validation failures are wrapped with context;
// use errors.Is for these.
var (
	ErrEmptyCipherList    = errors.New("tlsprint: cipher suite list is empty")
	ErrEmptyExtensionList = errors.New("tlsprint: extension list is empty")
	ErrDuplicateID        = errors.New("tlsprint: duplicate identifier in ordered list")
	ErrInvalidPseudoOrder = errors.New("tlsprint: invalid HTTP/2 pseudo-header order")
)

// Validate checks structural invariants of the profile and returns a
// descriptive error for the first problem found. A profile with no TLS list
// at all is considered valid (an empty fingerprint) unless requireTLS is set.
func (p *Profile) Validate() error {
	if p == nil {
		return nil
	}
	if err := p.TLS.Validate(); err != nil {
		return fmt.Errorf("tls profile: %w", err)
	}
	if p.HTTP2 != nil {
		if err := p.HTTP2.Validate(); err != nil {
			return fmt.Errorf("http2 profile: %w", err)
		}
	}
	if p.Headers != nil {
		if err := p.Headers.validate(); err != nil {
			return fmt.Errorf("header profile: %w", err)
		}
	}
	return nil
}

// Validate checks structural invariants of the TLS fingerprint lists.
//
// The ordered wire lists (cipher_suites, extensions, supported_groups,
// supported_versions) must each be duplicate-free; a ClientHello that lists
// extensions but no cipher suites, or carries group/version payloads without
// an extension list, is malformed. (signature_algorithms and the *_cert
// lists are deliberately exempted from the uniqueness check: real captures
// occasionally carry duplicate signature algorithms.)
//
// A completely empty profile is valid (an empty fingerprint); use
// ValidateStrict when a profile is required to describe a ClientHello.
func (t *TLSProfile) Validate() error {
	if t == nil {
		return nil
	}
	if err := checkUnique(t.CipherSuites, "cipher_suites"); err != nil {
		return err
	}
	if err := checkUnique(t.Extensions, "extensions"); err != nil {
		return err
	}
	if err := checkUnique(t.SupportedGroups, "supported_groups"); err != nil {
		return err
	}
	if err := checkUnique(t.SupportedVersions, "supported_versions"); err != nil {
		return err
	}
	if len(t.CipherSuites) == 0 && len(t.Extensions) > 0 {
		return ErrEmptyCipherList
	}
	if len(t.Extensions) == 0 && (len(t.SupportedVersions) > 0 || len(t.SupportedGroups) > 0) {
		return ErrEmptyExtensionList
	}
	return nil
}

// ValidateStrict additionally requires the profile to describe a ClientHello
// (a non-empty cipher list and extension list).
func (t *TLSProfile) ValidateStrict() error {
	if err := t.Validate(); err != nil {
		return err
	}
	if len(t.CipherSuites) == 0 {
		return ErrEmptyCipherList
	}
	if len(t.Extensions) == 0 {
		return ErrEmptyExtensionList
	}
	return nil
}

// Validate checks the HTTP/2 fingerprint.
func (h *HTTP2Profile) Validate() error {
	if h == nil {
		return nil
	}
	seen := make(map[uint16]bool, len(h.Settings))
	for _, s := range h.Settings {
		if seen[s.ID] {
			return fmt.Errorf("%w: settings id %d", ErrDuplicateID, s.ID)
		}
		seen[s.ID] = true
	}
	// Pseudo headers: at most one of each of the four standard ones, in any
	// order, all lowercase with a leading colon.
	seenP := make(map[string]bool, len(h.PseudoHeaderOrder))
	for _, ph := range h.PseudoHeaderOrder {
		lower := strings.ToLower(ph)
		switch lower {
		case ":method", ":authority", ":scheme", ":path":
		default:
			return fmt.Errorf("%w: %q", ErrInvalidPseudoOrder, ph)
		}
		if seenP[lower] {
			return fmt.Errorf("%w: duplicate %q", ErrInvalidPseudoOrder, ph)
		}
		seenP[lower] = true
	}
	return nil
}

func (h *HeaderProfile) validate() error {
	if h == nil {
		return nil
	}
	seen := make(map[string]bool, len(h.Order))
	for _, name := range h.Order {
		canon := canonicalHeader(name)
		if seen[canon] {
			return fmt.Errorf("%w: header %q", ErrDuplicateID, name)
		}
		seen[canon] = true
	}
	// Values may declare defaults for headers not listed in Order (the order
	// describes what a request sends; requests supply per-request values).
	for name := range h.Values {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("header profile: empty header name in values")
		}
	}
	return nil
}

// canonicalHeader returns the HTTP/2 canonical form of a header name:
// lower-case, as sent on the wire for h2, or MIME canonical for h1.
func canonicalHeader(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return n
	}
	// http/1.1 canonical form: uppercase first letter of each dash-part.
	parts := strings.Split(n, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "-")
}

func checkUnique(list []uint16, name string) error {
	seen := make(map[uint16]bool, len(list))
	for _, id := range list {
		if seen[id] {
			return fmt.Errorf("%w: %s id %d", ErrDuplicateID, name, id)
		}
		seen[id] = true
	}
	return nil
}

// HasExtension reports whether the extension type id appears in the ordered
// extension list.
func (t *TLSProfile) HasExtension(id uint16) bool {
	for _, e := range t.Extensions {
		if e == id {
			return true
		}
	}
	return false
}

// ExtensionIndex returns the position of extension type id in the ordered
// extension list, or -1.
func (t *TLSProfile) ExtensionIndex(id uint16) int {
	for i, e := range t.Extensions {
		if e == id {
			return i
		}
	}
	return -1
}
