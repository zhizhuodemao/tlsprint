package iana

import (
	"fmt"
	"sort"
	"strings"
)

// TLS protocol version ids as they appear in the ClientHello version field
// and in the supported_versions extension.
const (
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

// versionNames maps version ids to short names.
var versionNames = map[uint16]string{
	VersionSSL30: "ssl30",
	VersionTLS10: "tls10",
	VersionTLS11: "tls11",
	VersionTLS12: "tls12",
	VersionTLS13: "tls13",
}

// VersionName returns the short name ("tls12") for a protocol version id, or
// "" when unknown.
func VersionName(v uint16) string {
	return versionNames[v]
}

// VersionDisplay renders a version id as its name when known, else hex.
func VersionDisplay(v uint16) string {
	if n := versionNames[v]; n != "" {
		return n
	}
	return fmt.Sprintf("0x%04x", v)
}

// ParseVersionName parses a version name ("tls12", "1.3"), decimal value
// ("771"), or hex value ("0x0303") into the wire version id.
func ParseVersionName(s string) (id uint16, ok bool) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return 0, false
	}
	// Names like "1.3" / "1.2" (curl_cffi config style).
	decimal := map[string]uint16{
		"1.3": VersionTLS13, "1.2": VersionTLS12,
		"1.1": VersionTLS11, "1.0": VersionTLS10,
		"3.0": VersionSSL30,
	}
	if v, ok := decimal[t]; ok {
		return v, true
	}
	if v, valid := parseNumericID(t); valid {
		return v, true
	}
	for id, name := range versionNames {
		if name == t {
			return id, true
		}
	}
	return 0, false
}

// VersionNames returns a sorted list of all known version names.
func VersionNames() []string {
	out := make([]string, 0, len(versionNames))
	for _, n := range versionNames {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
