package hello

import (
	"reflect"
	"testing"

	"github.com/lingulingo/tlsprint"
	"github.com/lingulingo/tlsprint/iana"
)

// TestProfileWireRoundTrip builds a wire ClientHello from a semantic profile
// (ToClientHello), parses it back and confirms the ordered identifier lists
// survive the trip.
func TestProfileWireRoundTrip(t *testing.T) {
	p := &tlsprint.TLSProfile{
		LegacyVersion: 0x0303,
		CipherSuites:  []uint16{0x1301, 0x1302, 0x1303, 0x00ff},
		Extensions: []uint16{
			iana.ExtServerName,
			iana.ExtSupportedGroups,
			iana.ExtECPointFormats,
			iana.ExtSupportedVersions,
			iana.ExtSignatureAlgorithms,
			iana.ExtPSKKeyExchangeModes,
			0x4469, // unknown to the model: survives as type-only
		},
		SupportedGroups:     []uint16{iana.GreaseMarker, 29, 23, 24},
		ECFormats:           []byte{0},
		SupportedVersions:   []uint16{iana.GreaseMarker, 0x0304, 0x0303},
		SignatureAlgorithms: []uint16{0x0403, 0x0804, 0x0401},
		PSKKeyExchangeModes: []byte{1},
	}

	ch, err := ToClientHello(p)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ch.TLSProfile()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.CipherSuites, p.CipherSuites) {
		t.Fatalf("ciphers: %v != %v", back.CipherSuites, p.CipherSuites)
	}
	if !reflect.DeepEqual(back.Extensions, p.Extensions) {
		t.Fatalf("extensions: %v != %v", back.Extensions, p.Extensions)
	}
	if !reflect.DeepEqual(back.SupportedGroups, p.SupportedGroups) {
		t.Fatalf("groups: %v != %v", back.SupportedGroups, p.SupportedGroups)
	}
	if !reflect.DeepEqual(back.SupportedVersions, p.SupportedVersions) {
		t.Fatalf("versions: %v != %v", back.SupportedVersions, p.SupportedVersions)
	}
	if !reflect.DeepEqual(back.ECFormats, p.ECFormats) {
		t.Fatalf("ec formats: %v != %v", back.ECFormats, p.ECFormats)
	}
}
