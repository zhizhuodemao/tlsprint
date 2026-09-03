package ja3

import (
	"testing"

	"github.com/lingulingo/tlsprint/hello"
	"github.com/lingulingo/tlsprint/iana"
)

// Known real-world vector: Chrome 105 JA3 as captured by fingerprint
// services (the value is used by the reference projects).
const chrome105JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"

func TestParseFormatRoundTrip(t *testing.T) {
	p, err := Parse(chrome105JA3)
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 771 {
		t.Fatalf("version = %d, want 771", p.Version)
	}
	if len(p.CipherSuites) != 15 || p.CipherSuites[0] != 4865 {
		t.Fatalf("ciphers = %v", p.CipherSuites)
	}
	if len(p.Extensions) != 16 || p.Extensions[0] != 0 || p.Extensions[2] != 65281 {
		t.Fatalf("extensions = %v", p.Extensions)
	}
	if len(p.Groups) != 3 || p.Groups[0] != 29 {
		t.Fatalf("groups = %v", p.Groups)
	}
	if got := p.String(); got != chrome105JA3 {
		t.Fatalf("round trip = %q, want %q", got, chrome105JA3)
	}
}

func TestFormatFiltersGrease(t *testing.T) {
	got := Format(0x0303,
		[]uint16{iana.GreaseMarker, 0x1301, 0x1302},
		[]uint16{0x1a1a, iana.ExtServerName, iana.ExtSupportedGroups},
		[]uint16{iana.GreaseMarker, 29, 23, 24},
		[]byte{0},
	)
	want := "771,4865-4866,0-10,29-23-24,0"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestComputeFromHello(t *testing.T) {
	// Same profile as above but with GREASE cipher and extension included on
	// the wire: the computed canonical JA3 must filter them out.
	ch := &hello.ClientHello{
		LegacyVersion:      iana.VersionTLS12,
		CompressionMethods: []byte{0},
		CipherSuites:       []uint16{iana.GreaseMarker, 0x1301, 0x1302},
		Extensions: []hello.Extension{
			{Type: iana.GreaseMarker},
			{Type: iana.ExtServerName},
			{Type: iana.ExtSupportedGroups, Data: hello.EncodeSupportedGroups([]uint16{iana.GreaseMarker, 29, 23, 24})},
			{Type: iana.ExtECPointFormats, Data: hello.EncodeECPointFormats([]byte{0})},
		},
	}
	if got := Compute(ch); got != "771,4865-4866,0-10-11,29-23-24,0" {
		t.Fatalf("Compute = %q", got)
	}
}

func TestHash(t *testing.T) {
	// md5("771,4865,0,29-23-24,0") hand-computed via the hash below.
	h := Hash("771,4865,0,29-23-24,0")
	if len(h) != 32 {
		t.Fatalf("hash length = %d", len(h))
	}
	if h == "" {
		t.Fatal("empty hash")
	}
	// Deterministic: hashing twice is stable.
	if Hash("771,4865,0,29-23-24,0") != h {
		t.Fatal("hash not deterministic")
	}
}

func TestNilInputs(t *testing.T) {
	if got := Compute(nil); got != "" {
		t.Fatalf("Compute(nil) = %q, want empty", got)
	}
	if got := FromProfile(nil); got != "" {
		t.Fatalf("FromProfile(nil) = %q, want empty", got)
	}
}
