package iana

import (
	"fmt"
	"sort"
	"strings"
)

// Named group ids (IANA "TLS Supported Groups" registry).
const (
	GroupSecp256r1 = 23 // also P-256
	GroupSecp384r1 = 24 // also P-384
	GroupSecp521r1 = 25 // also P-521
	GroupSecp256k1 = 22
	GroupX25519    = 29
	GroupX448      = 30

	// GroupX25519MLKEM768 is the post-quantum hybrid (0x11ec) supported by
	// Go >= 1.24 and Chrome 131+.
	GroupX25519MLKEM768 = 0x11ec

	GroupFFDHE2048 = 256
	GroupFFDHE3072 = 257
	GroupFFDHE4096 = 258
	GroupFFDHE6144 = 259
	GroupFFDHE8192 = 260
)

// groupNames maps named-group ids to canonical names. Well-known aliases
// (P-256, x25519) are resolved in ParseGroupName.
var groupNames = map[uint16]string{
	22:     "secp256k1",
	23:     "secp256r1",
	24:     "secp384r1",
	25:     "secp521r1",
	29:     "x25519",
	30:     "x448",
	256:    "ffdhe2048",
	257:    "ffdhe3072",
	258:    "ffdhe4096",
	259:    "ffdhe6144",
	260:    "ffdhe8192",
	0x11ec: "x25519_mlkem768",
	0x11eb: "secp256r1_mlkem768",
}

// GroupName returns the canonical name for a group id, or "" when unknown.
func GroupName(id uint16) string {
	if IsGrease(id) {
		return ""
	}
	return groupNames[id]
}

// GroupDisplay renders a group id as its name when known, else hex.
func GroupDisplay(id uint16) string {
	if IsGrease(id) {
		return fmt.Sprintf("GREASE(0x%04x)", id)
	}
	if n := groupNames[id]; n != "" {
		return n
	}
	return fmt.Sprintf("0x%04x", id)
}

// ParseGroupName parses a group name ("x25519", "P-256", "secp256r1"),
// decimal id, or hex id into its numeric value.
func ParseGroupName(s string) (id uint16, ok bool) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return 0, false
	}
	if v, valid := parseNumericID(t); valid {
		return v, true
	}
	alias := map[string]string{
		"p-256": "secp256r1", "p256": "secp256r1", "prime256v1": "secp256r1",
		"p-384": "secp384r1", "p384": "secp384r1",
		"p-521": "secp521r1", "p521": "secp521r1",
		"x25519mlkem768": "x25519_mlkem768",
	}
	if canon, ok := alias[t]; ok {
		t = canon
	}
	for id, name := range groupNames {
		if name == t {
			return id, true
		}
	}
	return 0, false
}

// GroupNames returns a sorted list of all known group names.
func GroupNames() []string {
	out := make([]string, 0, len(groupNames))
	for _, n := range groupNames {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
