package tlsprint

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/lingulingo/tlsprint/iana"
)

func TestProfileValidate(t *testing.T) {
	p := &Profile{
		TLS: TLSProfile{
			CipherSuites: []uint16{0x1301, 0x1302},
			Extensions:   []uint16{0, 16},
		},
		HTTP2: &HTTP2Profile{
			PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		},
		Headers: &HeaderProfile{
			Order:  []string{"user-agent", "accept"},
			Values: map[string]string{"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestProfileValidateBadPseudoOrder(t *testing.T) {
	p := &Profile{TLS: TLSProfile{CipherSuites: []uint16{0x1301}}}
	p.HTTP2 = &HTTP2Profile{PseudoHeaderOrder: []string{":method", ":method"}}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "pseudo-header") {
		t.Fatalf("expected pseudo-header error, got %v", err)
	}
}

func TestProfileJSONRoundTrip(t *testing.T) {
	orig := &Profile{
		TLS: TLSProfile{
			LegacyVersion:       0x0303,
			CipherSuites:        []uint16{0x1301, 0x1302},
			Extensions:          []uint16{0, 43, 51},
			SupportedVersions:   []uint16{0x0a0a, 0x0304, 0x0303},
			SupportedGroups:     []uint16{0x0a0a, 29, 23, 24},
			SignatureAlgorithms: []uint16{0x0403, 0x0804},
			ECFormats:           []byte{0},
			RandomGrease:        true,
		},
		HTTP2: &HTTP2Profile{
			Settings:     []HTTP2Setting{{ID: 1, Value: 65536}, {ID: 4, Value: 6291456}},
			WindowUpdate: 15663105,
		},
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var got Profile
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.TLS.LegacyVersion != orig.TLS.LegacyVersion {
		t.Fatalf("LegacyVersion = %#x", got.TLS.LegacyVersion)
	}
	if len(got.TLS.CipherSuites) != 2 || got.TLS.CipherSuites[0] != 0x1301 {
		t.Fatalf("ciphers = %v", got.TLS.CipherSuites)
	}
	if len(got.TLS.SupportedVersions) != 3 || got.TLS.SupportedVersions[0] != 0x0a0a {
		t.Fatalf("versions = %v", got.TLS.SupportedVersions)
	}
	if got.HTTP2 == nil || got.HTTP2.WindowUpdate != 15663105 || len(got.HTTP2.Settings) != 2 {
		t.Fatalf("http2 = %+v", got.HTTP2)
	}
	if !got.TLS.RandomGrease {
		t.Fatal("RandomGrease lost")
	}
}

func TestHeaderUserAgentLookup(t *testing.T) {
	for _, key := range []string{"User-Agent", "user-agent"} {
		h := &HeaderProfile{Values: map[string]string{key: "test"}}
		if got := h.UserAgent(); got != "test" {
			t.Fatalf("UserAgent() = %q with key %q", got, key)
		}
	}
}

func TestGREASEHelpers(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xfafa} {
		if !iana.IsGrease(v) {
			t.Fatalf("%#x should be grease", v)
		}
	}
	for _, v := range []uint16{0x1301, 0x0304, 0x002f, 0x11ec} {
		if iana.IsGrease(v) {
			t.Fatalf("%#x should not be grease", v)
		}
	}
}

func TestTLSProfileValidateNegatives(t *testing.T) {
	// Extensions present but no ciphers -> malformed.
	if err := (&TLSProfile{Extensions: []uint16{0}}).Validate(); err != ErrEmptyCipherList {
		t.Fatalf("got %v, want ErrEmptyCipherList", err)
	}
	// Duplicate extension id -> structural error.
	if err := (&TLSProfile{CipherSuites: []uint16{0x1301}, Extensions: []uint16{0, 0}}).Validate(); !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("got %v, want ErrDuplicateID", err)
	}
	// Version/group payload without an extension list -> malformed.
	if err := (&TLSProfile{CipherSuites: []uint16{0x1301}, SupportedGroups: []uint16{29}}).Validate(); err != ErrEmptyExtensionList {
		t.Fatalf("got %v, want ErrEmptyExtensionList", err)
	}
	// Empty profile is valid (an empty fingerprint).
	if err := (&TLSProfile{}).Validate(); err != nil {
		t.Fatalf("empty profile should be valid, got %v", err)
	}
	// ValidateStrict requires a ClientHello.
	if err := (&TLSProfile{CipherSuites: []uint16{0x1301}, Extensions: []uint16{0}}).ValidateStrict(); err != nil {
		t.Fatalf("valid profile should pass ValidateStrict, got %v", err)
	}
	if err := (&TLSProfile{}).ValidateStrict(); err == nil {
		t.Fatal("ValidateStrict on empty profile should error")
	}
}
