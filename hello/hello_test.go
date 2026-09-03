package hello

import (
	"bytes"
	"errors"
	"testing"

	"github.com/lingulingo/tlsprint/iana"
)

// sampleHello returns a representative ClientHello for round-trip tests.
func sampleHello() *ClientHello {
	random := [32]byte{}
	for i := range random {
		random[i] = byte(i)
	}
	return &ClientHello{
		LegacyVersion:      iana.VersionTLS12,
		Random:             random,
		SessionID:          []byte{1, 2, 3},
		CipherSuites:       []uint16{iana.GreaseMarker, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0x009c, 0x00ff},
		CompressionMethods: []byte{0},
		Extensions: []Extension{
			{Type: iana.GreaseMarker, Data: nil},
			{Type: iana.ExtServerName, Data: []byte{0, 14, 0, 0, 11, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109}}, // "example.com"
			{Type: iana.ExtSupportedGroups, Data: EncodeSupportedGroups([]uint16{29, 23, 24, iana.GreaseMarker})},
			{Type: iana.ExtECPointFormats, Data: EncodeECPointFormats([]byte{0})},
			{Type: iana.ExtSupportedVersions, Data: EncodeSupportedVersions([]uint16{iana.GreaseMarker, 0x0304, 0x0303})},
			{Type: iana.ExtSignatureAlgorithms, Data: EncodeSignatureAlgorithms([]uint16{0x0403, 0x0804, 0x0401})},
			{Type: iana.ExtALPN, Data: EncodeALPN([]string{"h2", "http/1.1"})},
			{Type: 0x4469, Data: []byte{0, 0}}, // unknown body must survive untouched
		},
	}
}

func TestRoundTripHandshake(t *testing.T) {
	ch := sampleHello()
	wire, err := ch.MarshalHandshake()
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := ParseHandshake(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, mustHandshake(t, got)) {
		t.Fatal("handshake bytes differ after parse→build")
	}
	assertHelloEqual(t, ch, got)
}

func TestRoundTripRecord(t *testing.T) {
	ch := sampleHello()
	wire, err := ch.MarshalRecord(0) // record version = LegacyVersion
	if err != nil {
		t.Fatal(err)
	}
	got, version, err := ParseRecord(wire)
	if err != nil {
		t.Fatal(err)
	}
	if version != ch.LegacyVersion {
		t.Fatalf("record version = %#x, want %#x", version, ch.LegacyVersion)
	}
	rewire, err := got.MarshalRecord(0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, rewire) {
		t.Fatal("record bytes differ after parse→build")
	}
	assertHelloEqual(t, ch, got)
}

func TestParseAutoDetect(t *testing.T) {
	ch := sampleHello()
	for _, m := range []func(*ClientHello) ([]byte, error){
		(*ClientHello).MarshalHandshake,
		func(c *ClientHello) ([]byte, error) { return c.MarshalRecord(0) },
	} {
		wire, err := m(ch)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(wire)
		if err != nil {
			t.Fatal(err)
		}
		assertHelloEqual(t, ch, got)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		err  error
	}{
		{"empty", nil, ErrShortData},
		{"truncated record", []byte{0x16, 0x03, 0x01, 0x00, 0x20, 0x01}, ErrShortData},
		{"not handshake record", []byte{0x17, 0x03, 0x01, 0x00, 0x00}, ErrBadRecordType},
		{"bare non-client handshake", []byte{0x02, 0x00, 0x00, 0x00}, ErrBadHandshakeType},
		{"short body", []byte{0x03, 0x03, 0x00}, ErrShortData},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.data); !errors.Is(err, tc.err) {
				t.Fatalf("got %v, want %v", err, tc.err)
			}
		})
	}
}

func mustHandshake(t *testing.T, c *ClientHello) []byte {
	t.Helper()
	b, err := c.MarshalHandshake()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertHelloEqual(t *testing.T, want, got *ClientHello) {
	t.Helper()
	if want.LegacyVersion != got.LegacyVersion {
		t.Fatalf("LegacyVersion = %#x, want %#x", got.LegacyVersion, want.LegacyVersion)
	}
	if want.Random != got.Random {
		t.Fatal("Random differs")
	}
	if !bytes.Equal(want.SessionID, got.SessionID) {
		t.Fatal("SessionID differs")
	}
	if len(want.CipherSuites) != len(got.CipherSuites) {
		t.Fatalf("cipher count = %d, want %d", len(got.CipherSuites), len(want.CipherSuites))
	}
	for i := range want.CipherSuites {
		if want.CipherSuites[i] != got.CipherSuites[i] {
			t.Fatalf("cipher[%d] = %#x, want %#x", i, got.CipherSuites[i], want.CipherSuites[i])
		}
	}
	if !bytes.Equal(want.CompressionMethods, got.CompressionMethods) {
		t.Fatal("CompressionMethods differs")
	}
	if len(want.Extensions) != len(got.Extensions) {
		t.Fatalf("extension count = %d, want %d", len(got.Extensions), len(want.Extensions))
	}
	for i := range want.Extensions {
		w, g := want.Extensions[i], got.Extensions[i]
		if w.Type != g.Type || !bytes.Equal(w.Data, g.Data) {
			t.Fatalf("extension[%d] = {%#x %x}, want {%#x %x}", i, g.Type, g.Data, w.Type, w.Data)
		}
	}
}

func TestToTLSProfile(t *testing.T) {
	ch := sampleHello()
	p, err := ch.TLSProfile()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Extensions) != len(ch.Extensions) {
		t.Fatalf("extension order length %d, want %d", len(p.Extensions), len(ch.Extensions))
	}
	// Groups include the explicit GREASE marker from the wire.
	wantGroups := []uint16{29, 23, 24, iana.GreaseMarker}
	if len(p.SupportedGroups) != len(wantGroups) {
		t.Fatalf("groups = %v, want %v", p.SupportedGroups, wantGroups)
	}
	for i := range wantGroups {
		if p.SupportedGroups[i] != wantGroups[i] {
			t.Fatalf("groups[%d] = %#x, want %#x", i, p.SupportedGroups[i], wantGroups[i])
		}
	}
	if len(p.SupportedVersions) != 3 || p.SupportedVersions[0] != iana.GreaseMarker || p.SupportedVersions[1] != 0x0304 {
		t.Fatalf("versions = %v", p.SupportedVersions)
	}
	if len(p.SignatureAlgorithms) != 3 || p.SignatureAlgorithms[0] != 0x0403 {
		t.Fatalf("sigalgs = %v", p.SignatureAlgorithms)
	}
}
