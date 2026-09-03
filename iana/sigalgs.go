package iana

import (
	"fmt"
	"sort"
	"strings"
)

// Signature algorithm ids (IANA "TLS SignatureScheme" registry).
const (
	SigRSAPKCS1SHA1   = 0x0201
	SigRSAPKCS1SHA224 = 0x0301
	SigRSAPKCS1SHA256 = 0x0401
	SigRSAPKCS1SHA384 = 0x0501
	SigRSAPKCS1SHA512 = 0x0601

	SigECDSA_SHA1         = 0x0203
	SigECDSA_Secp224r1    = 0x0303
	SigECDSA_Secp256r1    = 0x0403
	SigECDSA_Secp384r1    = 0x0503
	SigECDSA_Secp521r1    = 0x0603
	SigEd25519            = 0x0807
	SigEd448              = 0x0808
	SigRSAPSS_RSAE_SHA256 = 0x0804
	SigRSAPSS_RSAE_SHA384 = 0x0805
	SigRSAPSS_RSAE_SHA512 = 0x0806
	SigRSAPSS_PSS_SHA256  = 0x0809
	SigRSAPSS_PSS_SHA384  = 0x080a
	SigRSAPSS_PSS_SHA512  = 0x080b
)

// sigAlgNames maps signature scheme ids to the snake_case names used by
// curl_cffi / peet.ws style fingerprint configs.
var sigAlgNames = map[uint16]string{
	0x0201: "rsa_pkcs1_sha1",
	0x0301: "rsa_pkcs1_sha224",
	0x0401: "rsa_pkcs1_sha256",
	0x0501: "rsa_pkcs1_sha384",
	0x0601: "rsa_pkcs1_sha512",
	0x0203: "ecdsa_sha1",
	0x0303: "ecdsa_secp224r1_sha224",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0809: "rsa_pss_pss_sha256",
	0x080a: "rsa_pss_pss_sha384",
	0x080b: "rsa_pss_pss_sha512",
}

// SigAlgName returns the snake_case name for a signature algorithm id, or ""
// when unknown.
func SigAlgName(id uint16) string {
	return sigAlgNames[id]
}

// SigAlgDisplay renders a signature algorithm id as its name when known,
// else hex.
func SigAlgDisplay(id uint16) string {
	if n := sigAlgNames[id]; n != "" {
		return n
	}
	return fmt.Sprintf("0x%04x", id)
}

// ParseSigAlgName parses a signature algorithm name (snake_case), decimal id,
// or hex id.
func ParseSigAlgName(s string) (id uint16, ok bool) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return 0, false
	}
	// Accept "name (0xNNNN)" form used by some dumps.
	if i := strings.Index(t, "(0x"); i >= 0 {
		if j := strings.Index(t[i:], ")"); j > 0 {
			t = t[i+1 : i+j]
		}
	}
	if v, valid := parseNumericID(t); valid {
		return v, true
	}
	for id, name := range sigAlgNames {
		if name == t {
			return id, true
		}
	}
	return 0, false
}

// SigAlgNames returns a sorted list of all known signature algorithm names.
func SigAlgNames() []string {
	out := make([]string, 0, len(sigAlgNames))
	for _, n := range sigAlgNames {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
