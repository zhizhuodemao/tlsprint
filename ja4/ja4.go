// Package ja4 implements the JA4 TLS fingerprint format
// (https://github.com/FoxIO-LLC/ja4), the modern successor of JA3.
//
// JA4 splits the ClientHello fingerprint into an "_a" descriptive section and
// two hash sections ("_b" over sorted ciphers, "_c" over sorted extensions +
// signature algorithms). Unlike JA3 it is GREASE-robust by construction and
// depends on SNI/ALPN presence rather than absolute values, so it is stable
// across domains.
//
// Only the TLS-over-TCP flavour ("t") is implemented here. QUIC/DTLS
// fingerprints need transport-level framing that is out of scope for a
// ClientHello library; the tr/version/count fields they share are exposed so
// higher layers can build on them.
package ja4

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/lingulingo/tlsprint/hello"
	"github.com/lingulingo/tlsprint/iana"
)

// JA4 is one parsed JA4 fingerprint: "A_B_C".
type JA4 struct {
	// A is the descriptive section, e.g. "t13d1516h2".
	A string
	// B is the truncated cipher hash, e.g. "8daaf6152771".
	B string
	// C is the truncated extension+sigalgs hash, e.g. "e5627efa2ab1".
	C string
}

// String renders the full "A_B_C" fingerprint.
func (j JA4) String() string {
	return j.A + "_" + j.B + "_" + j.C
}

// Compute derives the JA4 fingerprint from a parsed ClientHello.
func Compute(ch *hello.ClientHello) (JA4, error) {
	if ch == nil {
		return JA4{}, fmt.Errorf("ja4: nil client hello")
	}
	a, err := computeA(ch)
	if err != nil {
		return JA4{}, err
	}
	b := computeB(ch)
	c := computeC(ch)
	return JA4{A: a, B: b, C: c}, nil
}

// transport is always "t" (TLS over TCP) in this library.
const transport = "t"

// computeA builds the descriptive section:
//
//	<transport><tls version><d|i><## ciphers><## extensions><alpn>
func computeA(ch *hello.ClientHello) (string, error) {
	var sb strings.Builder
	sb.WriteString(transport)
	sb.WriteString(versionString(ch))

	if _, ok := ch.FindExtension(iana.ExtServerName); ok {
		sb.WriteString("d")
	} else {
		sb.WriteString("i")
	}

	cipherCount := 0
	for _, cs := range ch.CipherSuites {
		if !iana.IsGrease(cs) {
			cipherCount++
		}
	}
	sb.WriteString(pad2(cipherCount))

	extCount := 0
	for _, e := range ch.Extensions {
		if !iana.IsGrease(e.Type) {
			extCount++
		}
	}
	sb.WriteString(pad2(extCount))

	alpn, err := firstALPN(ch)
	if err != nil {
		return "", err
	}
	sb.WriteString(alpnChars(alpn))
	return sb.String(), nil
}

// computeB builds the truncated sha256 of the sorted, GREASE-free cipher list.
func computeB(ch *hello.ClientHello) string {
	var list []string
	for _, cs := range ch.CipherSuites {
		if iana.IsGrease(cs) {
			continue
		}
		list = append(list, fmt.Sprintf("%04x", cs))
	}
	if len(list) == 0 {
		return "000000000000"
	}
	sort.Strings(list)
	return hash12(strings.Join(list, ","))
}

// computeC builds the truncated sha256 of the sorted extension list (SNI and
// ALPN removed, GREASE removed) followed by the signature algorithms in
// appearance order.
func computeC(ch *hello.ClientHello) string {
	var list []string
	for _, e := range ch.Extensions {
		t := e.Type
		if iana.IsGrease(t) || t == iana.ExtServerName || t == iana.ExtALPN {
			continue
		}
		list = append(list, fmt.Sprintf("%04x", t))
	}
	if len(list) == 0 {
		return "000000000000"
	}
	sort.Strings(list)
	joined := strings.Join(list, ",")

	if e, ok := ch.FindExtension(iana.ExtSignatureAlgorithms); ok {
		if algs, err := hello.DecodeSignatureAlgorithms(e.Data); err == nil {
			// GREASE is ignored everywhere in JA4 (spec), including the
			// signature-algorithm list (Chrome introduces a GREASE sigalg).
			var sig []string
			for _, a := range algs {
				if iana.IsGrease(a) {
					continue
				}
				sig = append(sig, fmt.Sprintf("%04x", a))
			}
			if len(sig) > 0 {
				joined += "_" + strings.Join(sig, ",")
			}
		}
	}
	return hash12(joined)
}

// versionString returns the two-character TLS version code. When the
// supported_versions extension is present its highest non-GREASE value wins;
// otherwise the ClientHello legacy version is used.
func versionString(ch *hello.ClientHello) string {
	if e, ok := ch.FindExtension(iana.ExtSupportedVersions); ok {
		if versions, err := hello.DecodeSupportedVersions(e.Data); err == nil {
			max := uint16(0)
			for _, v := range versions {
				if iana.IsGrease(v) {
					continue
				}
				if v > max {
					max = v
				}
			}
			if max != 0 {
				return versionCode(max)
			}
		}
	}
	return versionCode(ch.LegacyVersion)
}

func versionCode(v uint16) string {
	switch v {
	case iana.VersionTLS13:
		return "13"
	case iana.VersionTLS12:
		return "12"
	case iana.VersionTLS11:
		return "11"
	case iana.VersionTLS10:
		return "10"
	case iana.VersionSSL30:
		return "s3"
	case 0x0002:
		return "s2"
	}
	return "00"
}

// firstALPN returns the first ALPN protocol value, or "" when the extension
// is absent or empty. A malformed ALPN extension is reported as an error.
func firstALPN(ch *hello.ClientHello) (string, error) {
	e, ok := ch.FindExtension(iana.ExtALPN)
	if !ok {
		return "", nil
	}
	protos, err := hello.DecodeALPN(e.Data)
	if err != nil {
		return "", fmt.Errorf("ja4: alpn: %w", err)
	}
	if len(protos) == 0 {
		return "", nil
	}
	return protos[0], nil
}

// alpnChars renders the two-character ALPN section of the _a part.
//
// If both the first and last byte of the first ALPN value are ASCII
// alphanumeric, those bytes are used directly ("h2", "h1"). Otherwise the
// first and last characters of the lower-case hex representation of the value
// are used (see the JA4 specification, section "ALPN Extension Value").
func alpnChars(alpn string) string {
	if alpn == "" {
		return "00"
	}
	first := alpn[0]
	last := alpn[len(alpn)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	hexStr := hex.EncodeToString([]byte(alpn))
	return hexStr[0:1] + hexStr[len(hexStr)-1:]
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

func pad2(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// ParseCounts renders the two count fields of the _a part without a full
// ClientHello; useful for tooling that only needs the descriptive bits.
func ParseCounts(numCiphers, numExtensions int) (ciphers, extensions string) {
	return pad2(numCiphers), pad2(numExtensions)
}
