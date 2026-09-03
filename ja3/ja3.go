// Package ja3 implements the JA3 TLS fingerprint string format.
//
// JA3 fingerprints are the de-facto industry standard TLS ClientHello
// signature: "SSLVersion,Ciphers,Extensions,Groups,PointFormats" with each
// list dash-joined and the whole string MD5-hashed in the classic hash form.
//
// tlsprint implements both views:
//
//   - The canonical *string* (the 5 dash/comma-separated parts) via Format,
//     which is what fingerprint services (tls.peet.ws, Cloudflare research)
//     publish and compare. GREASE values are excluded from the string, which
//     matches the ecosystem convention.
//   - The *hash* (md5 of the canonical string, the traditional JA3 id) via
//     Hash.
//
// JA3 does not capture extension *order* semantically (it is order
// preserving as sent on the wire, with GREASE removed) and tells you nothing
// about extension payloads; for byte-level work see the hello package and
// for the successor format see package ja4.
package ja3

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/lingulingo/tlsprint"
	"github.com/lingulingo/tlsprint/hello"
	"github.com/lingulingo/tlsprint/iana"
)

// Parts is a parsed JA3 string split into its five sections.
type Parts struct {
	// Version is the decimal ClientHello legacy version, e.g. 771.
	Version uint16
	// CipherSuites is the cipher suite list (GREASE-free).
	CipherSuites []uint16
	// Extensions is the extension type list in wire order (GREASE-free).
	Extensions []uint16
	// Groups is the supported_groups list (GREASE-free).
	Groups []uint16
	// ECFormats is the ec_point_formats list.
	ECFormats []byte
}

// String renders the canonical JA3 string.
func (p *Parts) String() string {
	return Format(p.Version, p.CipherSuites, p.Extensions, p.Groups, p.ECFormats)
}

// TLSProfile converts the parsed parts into the semantic TLS fingerprint
// model. The legacy version is mapped to 0x0303 (the value every modern
// client sends, corresponding to "771").
func (p *Parts) TLSProfile() *tlsprint.TLSProfile {
	legacy := p.Version
	if legacy == 0 {
		legacy = 771
	}
	return &tlsprint.TLSProfile{
		LegacyVersion:   legacy,
		CipherSuites:    append([]uint16(nil), p.CipherSuites...),
		Extensions:      append([]uint16(nil), p.Extensions...),
		SupportedGroups: append([]uint16(nil), p.Groups...),
		ECFormats:       append([]byte(nil), p.ECFormats...),
	}
}

// Compute derives the canonical JA3 string from a parsed ClientHello.
// GREASE values are excluded from every list, following the ecosystem
// convention that fingerprint services report GREASE-free JA3 strings.
// A nil ClientHello yields an empty string (it does not panic).
func Compute(ch *hello.ClientHello) string {
	if ch == nil {
		return ""
	}
	groups := groupsFromHello(ch)
	formats := formatsFromHello(ch)
	return Format(ch.LegacyVersion, ch.CipherSuites, extensionTypes(ch), groups, formats)
}

// FromProfile derives the canonical JA3 string from a semantic TLS profile.
// The ClientHello legacy version is assumed to be 0x0303 ("771"), the value
// sent by every modern TLS client. A nil profile yields an empty string.
func FromProfile(p *tlsprint.TLSProfile) string {
	if p == nil {
		return ""
	}
	ver := p.LegacyVersion
	if ver == 0 {
		ver = 0x0303
	}
	return Format(ver, p.CipherSuites, p.Extensions, p.SupportedGroups, p.ECFormats)
}

// Format renders the canonical JA3 string from its parts, filtering GREASE
// values out of the identifier lists.
func Format(version uint16, ciphers, extensions, groups []uint16, ecFormats []byte) string {
	var sb strings.Builder
	sb.WriteString(strconv.Itoa(int(version)))
	sb.WriteString(",")
	sb.WriteString(joinHexFiltered(ciphers))
	sb.WriteString(",")
	sb.WriteString(joinHexFiltered(extensions))
	sb.WriteString(",")
	sb.WriteString(joinHexFiltered(groups))
	sb.WriteString(",")
	sb.WriteString(joinDec(ecFormats))
	return sb.String()
}

// Parse parses a JA3 string into its parts. Whitespace is tolerated.
func Parse(s string) (*Parts, error) {
	fields := strings.Split(strings.TrimSpace(s), ",")
	if len(fields) != 5 {
		return nil, fmt.Errorf("ja3: expected 5 comma-separated fields, got %d", len(fields))
	}
	p := &Parts{}
	ver, err := strconv.ParseUint(strings.TrimSpace(fields[0]), 10, 16)
	if err != nil {
		return nil, fmt.Errorf("ja3: bad version %q", fields[0])
	}
	p.Version = uint16(ver)
	if p.CipherSuites, err = parseU16List(fields[1], "-"); err != nil {
		return nil, fmt.Errorf("ja3: ciphers: %w", err)
	}
	if p.Extensions, err = parseU16List(fields[2], "-"); err != nil {
		return nil, fmt.Errorf("ja3: extensions: %w", err)
	}
	if p.Groups, err = parseU16List(fields[3], "-"); err != nil {
		return nil, fmt.Errorf("ja3: groups: %w", err)
	}
	if p.ECFormats, err = parseU8List(fields[4], "-"); err != nil {
		return nil, fmt.Errorf("ja3: point formats: %w", err)
	}
	return p, nil
}

// Hash returns the classic JA3 hash: the MD5 of the canonical string,
// hex-encoded. This is the identifier used by most fingerprint databases.
func Hash(ja3 string) string {
	sum := md5.Sum([]byte(ja3))
	return hex.EncodeToString(sum[:])
}

// HashParts is Hash applied to a Parts value.
func HashParts(p *Parts) string {
	return Hash(p.String())
}

func joinHexFiltered(ids []uint16) string {
	var sb strings.Builder
	first := true
	for _, id := range ids {
		if iana.IsGrease(id) {
			continue
		}
		if !first {
			sb.WriteString("-")
		}
		first = false
		sb.WriteString(strconv.Itoa(int(id)))
	}
	return sb.String()
}

func joinDec(ids []byte) string {
	var sb strings.Builder
	for i, id := range ids {
		if i > 0 {
			sb.WriteString("-")
		}
		sb.WriteString(strconv.Itoa(int(id)))
	}
	return sb.String()
}

func parseU16List(s, sep string) ([]uint16, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	parts := strings.Split(s, sep)
	out := make([]uint16, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("bad id %q", part)
		}
		out = append(out, uint16(v))
	}
	return out, nil
}

func parseU8List(s, sep string) ([]byte, error) {
	u16s, err := parseU16List(s, sep)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(u16s))
	for i, v := range u16s {
		if v > 255 {
			return nil, fmt.Errorf("value %d out of byte range", v)
		}
		out[i] = byte(v)
	}
	return out, nil
}

func extensionTypes(ch *hello.ClientHello) []uint16 {
	out := make([]uint16, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		out = append(out, e.Type)
	}
	return out
}

func groupsFromHello(ch *hello.ClientHello) []uint16 {
	if e, ok := ch.FindExtension(iana.ExtSupportedGroups); ok {
		if groups, err := hello.DecodeSupportedGroups(e.Data); err == nil {
			return groups
		}
	}
	return nil
}

func formatsFromHello(ch *hello.ClientHello) []byte {
	if e, ok := ch.FindExtension(iana.ExtECPointFormats); ok {
		if formats, err := hello.DecodeECPointFormats(e.Data); err == nil {
			return formats
		}
	}
	return nil
}
