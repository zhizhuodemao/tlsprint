package ja4

import (
	"testing"

	"github.com/lingulingo/tlsprint/hello"
	"github.com/lingulingo/tlsprint/iana"
)

// buildSpecExample reconstructs the ClientHello from the JA4 specification's
// running example:
//
//	JA4 = t13d1516h2_8daaf6152771_e5627efa2ab1
func buildSpecExample() *hello.ClientHello {
	random := [32]byte{}
	ciphers := []uint16{
		0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
		0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
	}
	// 16 extensions as listed in the spec's "-o" (original order) example.
	extTypes := []uint16{
		0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
		0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
	}
	ch := &hello.ClientHello{
		LegacyVersion:      iana.VersionTLS12,
		Random:             random,
		CipherSuites:       ciphers,
		CompressionMethods: []byte{0},
	}
	for _, typ := range extTypes {
		var data []byte
		switch typ {
		case iana.ExtALPN:
			data = hello.EncodeALPN([]string{"h2"})
		case iana.ExtServerName:
			data = []byte{0, 14, 0, 0, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}
		case iana.ExtSupportedVersions:
			data = hello.EncodeSupportedVersions([]uint16{iana.VersionTLS13, iana.VersionTLS12})
		case iana.ExtSignatureAlgorithms:
			data = hello.EncodeSignatureAlgorithms([]uint16{
				0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
			})
		}
		ch.Extensions = append(ch.Extensions, hello.Extension{Type: typ, Data: data})
	}
	return ch
}

func TestComputeSpecExample(t *testing.T) {
	j, err := Compute(buildSpecExample())
	if err != nil {
		t.Fatal(err)
	}
	want := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if got := j.String(); got != want {
		t.Fatalf("JA4 = %q, want %q", got, want)
	}
}

func TestComputeNoSNI(t *testing.T) {
	ch := buildSpecExample()
	ch.RemoveExtensions(iana.ExtServerName)
	j, err := Compute(ch)
	if err != nil {
		t.Fatal(err)
	}
	// A = t 13 i 15 15 h2 — index 3 is the SNI marker.
	if j.A[3] != 'i' {
		t.Fatalf("expected 'i' for missing SNI, got %q", j.A)
	}
	if got := j.String(); got[:8] != "t13i1515" {
		t.Fatalf("unexpected prefix %q", got)
	}
}

func TestComputeGreaseIgnored(t *testing.T) {
	ch := buildSpecExample()
	// Inject GREASE cipher and extension: they must not affect the result.
	ch.CipherSuites = append([]uint16{iana.GreaseMarker}, ch.CipherSuites...)
	ch.Extensions = append([]hello.Extension{{Type: iana.GreaseMarker}}, ch.Extensions...)
	before, err := Compute(buildSpecExample())
	if err != nil {
		t.Fatal(err)
	}
	after, err := Compute(ch)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("GREASE changed JA4: %q vs %q", before, after)
	}
}

func TestNoALPN(t *testing.T) {
	ch := buildSpecExample()
	ch.RemoveExtensions(iana.ExtALPN)
	j, err := Compute(ch)
	if err != nil {
		t.Fatal(err)
	}
	if j.A[len(j.A)-2:] != "00" {
		t.Fatalf("expected alpn 00, got %q", j.A)
	}
}

func TestAlpnChars(t *testing.T) {
	cases := []struct {
		alpn string
		want string
	}{
		{"h2", "h2"},
		{"http/1.1", "h1"},
		{"", "00"},
		{"\xab", "ab"},             // single non-alnum byte
		{"\x20", "20"},             // single space
		{"\xab\xcd", "ad"},         // both non-alnum
		{"\x20a", "21"},            // first non-alnum, last alnum
		{"a\x20", "60"},            // first alnum, last non-alnum
		{"01\xab\xcd", "3d"},       // last non-alnum
		{"0\xab\xcd1", "01"},       // both ends alnum → direct
		{"\x30\xab", "3b"},         // spec bullet
		{"\x20\x61", "21"},         // spec bullet
		{"\x61\x20", "60"},         // spec bullet
		{"\x30\xab\xcd\x31", "01"}, // spec bullet
	}
	for _, tc := range cases {
		if got := alpnChars(tc.alpn); got != tc.want {
			t.Errorf("alpnChars(%q) = %q, want %q", tc.alpn, got, tc.want)
		}
	}
}

func TestVersionCode(t *testing.T) {
	if versionCode(iana.VersionTLS13) != "13" {
		t.Fatal("tls13")
	}
	if versionCode(iana.VersionTLS12) != "12" {
		t.Fatal("tls12")
	}
	if versionCode(iana.VersionSSL30) != "s3" {
		t.Fatal("s3")
	}
	if versionCode(0x1234) != "00" {
		t.Fatal("unknown")
	}
}
