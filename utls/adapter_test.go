package utls

import (
	"testing"

	"github.com/lingulingo/tlsprint"
	"github.com/lingulingo/tlsprint/iana"
	"github.com/lingulingo/tlsprint/preset"
	utls "github.com/refraction-networking/utls"
)

func TestFromPresetChrome(t *testing.T) {
	reg := preset.MustBuiltin()
	p := reg.Lookup("TLS_CHROME_141")
	if p == nil {
		t.Fatal("chrome preset not found")
	}
	spec, err := FromPreset(p)
	if err != nil {
		t.Fatal(err)
	}

	// GREASE cipher in front, then the profile's ciphers verbatim.
	if len(spec.CipherSuites) != len(p.TLS.CipherSuites)+1 {
		t.Fatalf("cipher count = %d, want %d", len(spec.CipherSuites), len(p.TLS.CipherSuites)+1)
	}
	if spec.CipherSuites[0] != utls.GREASE_PLACEHOLDER {
		t.Fatalf("first cipher = %#x, want GREASE placeholder", spec.CipherSuites[0])
	}
	for i, cs := range p.TLS.CipherSuites {
		if spec.CipherSuites[i+1] != cs {
			t.Fatalf("cipher[%d] = %#x, want %#x", i+1, spec.CipherSuites[i+1], cs)
		}
	}

	// GREASE extension first; the rest follows the profile's extension order,
	// minus session-resumption extensions (41/42) dropped by default.
	var wantTypes []uint16
	for _, typ := range p.TLS.Extensions {
		if typ == iana.ExtPreSharedKey || typ == iana.ExtEarlyData {
			continue // session-resumption extensions are not sent on fresh
		}
		wantTypes = append(wantTypes, typ)
	}
	if len(spec.Extensions) != len(wantTypes)+1 {
		t.Fatalf("extension count = %d, want %d", len(spec.Extensions), len(wantTypes)+1)
	}
	if _, ok := spec.Extensions[0].(*utls.UtlsGREASEExtension); !ok {
		t.Fatalf("first extension is %T, want UtlsGREASEExtension", spec.Extensions[0])
	}
	for i, want := range wantTypes {
		got := typeOf(spec.Extensions[i+1])
		if got != want {
			t.Fatalf("extension[%d] = %#x, want %#x", i+1, got, want)
		}
	}

	// Supported versions payload translated from the profile.
	if p.TLS.SupportedVersions != nil {
		sv := findExtension[*utls.SupportedVersionsExtension](spec)
		if sv == nil {
			t.Fatal("supported_versions extension missing")
		}
		if len(sv.Versions) != len(p.TLS.SupportedVersions) {
			t.Fatalf("versions len %d != %d", len(sv.Versions), len(p.TLS.SupportedVersions))
		}
	}
}

func TestFromProfileNoGrease(t *testing.T) {
	p := &tlsprint.TLSProfile{
		LegacyVersion: iana.VersionTLS12,
		CipherSuites:  []uint16{0x1301, 0x1302},
		Extensions: []uint16{
			iana.ExtServerName,
			iana.ExtSupportedGroups,
			iana.ExtSupportedVersions,
			iana.ExtSignatureAlgorithms,
		},
		SupportedVersions:   []uint16{iana.VersionTLS13, iana.VersionTLS12},
		SignatureAlgorithms: []uint16{0x0403, 0x0804},
		SupportedGroups:     []uint16{iana.GreaseMarker, iana.GroupX25519, iana.GroupSecp256r1},
	}

	spec, err := FromProfile(p, &Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.CipherSuites) != 2 || spec.CipherSuites[0] != 0x1301 {
		t.Fatalf("unexpected ciphers %v", spec.CipherSuites)
	}
	if len(spec.Extensions) != 4 {
		t.Fatalf("extension count = %d", len(spec.Extensions))
	}
	curves := findExtension[*utls.SupportedCurvesExtension](spec)
	if curves == nil {
		t.Fatal("supported_groups extension missing")
	}
	if len(curves.Curves) != 3 || !iana.IsGrease(uint16(curves.Curves[0])) {
		t.Fatalf("curves = %v (first must be a randomized GREASE value)", curves.Curves)
	}
	// TLSVers range derived from supported_versions.
	if spec.TLSVersMax != iana.VersionTLS13 || spec.TLSVersMin != iana.VersionTLS12 {
		t.Fatalf("version range %#x-%#x", spec.TLSVersMin, spec.TLSVersMax)
	}
}

func TestUnknownExtensionPassthrough(t *testing.T) {
	p := &tlsprint.TLSProfile{
		CipherSuites:    []uint16{0x1301},
		Extensions:      []uint16{0x1234, iana.ExtALPN},
		ExtraExtensions: map[uint16][]byte{0x1234: {1, 2, 3}},
	}
	spec, err := FromProfile(p, &Options{ALPN: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Extensions) != 2 {
		t.Fatalf("extensions = %d", len(spec.Extensions))
	}
	if g, ok := spec.Extensions[0].(*utls.GenericExtension); !ok || g.Id != 0x1234 {
		t.Fatalf("ext[0] = %T, want GenericExtension(0x1234)", spec.Extensions[0])
	} else if len(g.Data) != 3 || g.Data[0] != 1 {
		t.Fatalf("ext[0].Data = %v", g.Data)
	}
	if a, ok := spec.Extensions[1].(*utls.ALPNExtension); !ok {
		t.Fatalf("ext[1] = %T, want ALPNExtension", spec.Extensions[1])
	} else if len(a.AlpnProtocols) != 1 || a.AlpnProtocols[0] != "h2" {
		t.Fatalf("alpn = %v", a.AlpnProtocols)
	}
}

func TestUnknownExtensionWithoutPayloadIsSkipped(t *testing.T) {
	p := &tlsprint.TLSProfile{
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{0x1234}, // no ExtraExtensions payload
	}
	spec, err := FromProfile(p, &Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Extensions) != 0 {
		t.Fatalf("extensions = %d, want 0 (unknown no-payload omitted)", len(spec.Extensions))
	}
}

func TestKeyShareSelection(t *testing.T) {
	p := &tlsprint.TLSProfile{
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{iana.ExtKeyShare},
		SupportedGroups: []uint16{
			iana.GreaseMarker,
			iana.GroupX25519MLKEM768, iana.GroupX25519,
			iana.GroupSecp256r1, iana.GroupSecp384r1,
			256, // ffdhe2048 — not keyshare-capable
		},
	}
	spec, err := FromProfile(p, &Options{})
	if err != nil {
		t.Fatal(err)
	}
	ks, ok := spec.Extensions[0].(*utls.KeyShareExtension)
	if !ok {
		t.Fatalf("ext = %T", spec.Extensions[0])
	}
	if len(ks.KeyShares) != 2 {
		t.Fatalf("keyshares = %d, want 2", len(ks.KeyShares))
	}
	if ks.KeyShares[0].Group != utls.CurveID(iana.GroupX25519MLKEM768) {
		t.Fatalf("keyshare[0] group = %d", ks.KeyShares[0].Group)
	}
	if ks.KeyShares[1].Group != utls.CurveID(iana.GroupX25519) {
		t.Fatalf("keyshare[1] group = %d", ks.KeyShares[1].Group)
	}
}

func findExtension[T any](spec *utls.ClientHelloSpec) T {
	var zero T
	for _, e := range spec.Extensions {
		if v, ok := e.(T); ok {
			return v
		}
	}
	return zero
}

func typeOf(e utls.TLSExtension) uint16 {
	switch v := e.(type) {
	case *utls.SNIExtension:
		return iana.ExtServerName
	case *utls.SupportedCurvesExtension:
		return iana.ExtSupportedGroups
	case *utls.SupportedPointsExtension:
		return iana.ExtECPointFormats
	case *utls.SignatureAlgorithmsExtension:
		return iana.ExtSignatureAlgorithms
	case *utls.SignatureAlgorithmsCertExtension:
		return iana.ExtSignatureAlgorithmsCert
	case *utls.ALPNExtension:
		return iana.ExtALPN
	case *utls.SCTExtension:
		return iana.ExtSignedCertificateTimestamp
	case *utls.UtlsPaddingExtension:
		return iana.ExtPadding
	case *utls.ExtendedMasterSecretExtension:
		return iana.ExtExtendedMasterSecret
	case *utls.UtlsCompressCertExtension:
		return iana.ExtCompressCertificate
	case *utls.FakeRecordSizeLimitExtension:
		return iana.ExtRecordSizeLimit
	case *utls.FakeDelegatedCredentialsExtension:
		return iana.ExtDelegatedCredentials
	case *utls.SessionTicketExtension:
		return iana.ExtSessionTicket
	case *utls.SupportedVersionsExtension:
		return iana.ExtSupportedVersions
	case *utls.PSKKeyExchangeModesExtension:
		return iana.ExtPSKKeyExchangeModes
	case *utls.KeyShareExtension:
		return iana.ExtKeyShare
	case *utls.ApplicationSettingsExtension:
		return iana.ExtApplicationSettings
	case *utls.ApplicationSettingsExtensionNew:
		return 17613
	case *utls.GREASEEncryptedClientHelloExtension:
		return iana.ExtEncryptedClientHello
	case *utls.RenegotiationInfoExtension:
		return iana.ExtRenegotiationInfo
	case *utls.StatusRequestExtension:
		return iana.ExtStatusRequest
	case *utls.GenericExtension:
		return v.Id
	case *utls.UtlsGREASEExtension:
		return iana.GreaseMarker
	default:
		return 0xffff
	}
}
