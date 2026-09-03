package iana

import (
	"fmt"
	"sort"
	"strings"
)

// Extension type ids (RFC 8446 §4.2 and IANA "TLS ExtensionType Values").
// Values without a well-known constant are still handled numerically.
const (
	ExtServerName                 = 0
	ExtMaxFragmentLength          = 1
	ExtClientCertificateURL       = 2
	ExtTrustedCAKeys              = 3
	ExtTruncatedHMAC              = 4
	ExtStatusRequest              = 5
	ExtUserMapping                = 6
	ExtClientAuthz                = 7
	ExtServerAuthz                = 8
	ExtCertificateType            = 9
	ExtSupportedGroups            = 10
	ExtECPointFormats             = 11
	ExtSRP                        = 12
	ExtSignatureAlgorithms        = 13
	ExtUseSRTP                    = 14
	ExtHeartbeat                  = 15
	ExtALPN                       = 16
	ExtStatusRequestV2            = 17
	ExtSignedCertificateTimestamp = 18
	ExtClientCertificateType      = 19
	ExtServerCertificateType      = 20
	ExtPadding                    = 21
	ExtEncryptThenMAC             = 22
	ExtExtendedMasterSecret       = 23
	ExtTokenBinding               = 24
	ExtCachedInfo                 = 25
	ExtCompressCertificate        = 27
	ExtRecordSizeLimit            = 28
	ExtDelegatedCredentials       = 34
	ExtSessionTicket              = 35
	ExtPreSharedKey               = 41
	ExtEarlyData                  = 42
	ExtSupportedVersions          = 43
	ExtCookie                     = 44
	ExtPSKKeyExchangeModes        = 45
	ExtCertificateAuthorities     = 47
	ExtOIDFilters                 = 48
	ExtPostHandshakeAuth          = 49
	ExtSignatureAlgorithmsCert    = 50
	ExtKeyShare                   = 51

	// RenegotiationInfo is 0xFF01.
	ExtRenegotiationInfo = 65281

	// ExtEncryptedClientHello is 0xFE0D (draft-ietf-tls-esni).
	ExtEncryptedClientHello = 65037

	// ExtApplicationSettings is 0x4469 ("ALPS", draft-vvv-tls-alps).
	ExtApplicationSettings = 17513

	// ExtQUICTransportParameters is 0x0039 (RFC 9001).
	ExtQUICTransportParameters = 57
)

// extensionNames maps extension type ids to canonical IANA-ish names
// (snake_case, no "extension_" prefix).
var extensionNames = map[uint16]string{
	ExtServerName:                 "server_name",
	ExtMaxFragmentLength:          "max_fragment_length",
	ExtClientCertificateURL:       "client_certificate_url",
	ExtTrustedCAKeys:              "trusted_ca_keys",
	ExtTruncatedHMAC:              "truncated_hmac",
	ExtStatusRequest:              "status_request",
	ExtUserMapping:                "user_mapping",
	ExtClientAuthz:                "client_authz",
	ExtServerAuthz:                "server_authz",
	ExtCertificateType:            "certificate_type",
	ExtSupportedGroups:            "supported_groups",
	ExtECPointFormats:             "ec_point_formats",
	ExtSRP:                        "srp",
	ExtSignatureAlgorithms:        "signature_algorithms",
	ExtUseSRTP:                    "use_srtp",
	ExtHeartbeat:                  "heartbeat",
	ExtALPN:                       "application_layer_protocol_negotiation",
	ExtStatusRequestV2:            "status_request_v2",
	ExtSignedCertificateTimestamp: "signed_certificate_timestamp",
	ExtClientCertificateType:      "client_certificate_type",
	ExtServerCertificateType:      "server_certificate_type",
	ExtPadding:                    "padding",
	ExtEncryptThenMAC:             "encrypt_then_mac",
	ExtExtendedMasterSecret:       "extended_master_secret",
	ExtTokenBinding:               "token_binding",
	ExtCachedInfo:                 "cached_info",
	ExtCompressCertificate:        "compress_certificate",
	ExtRecordSizeLimit:            "record_size_limit",
	ExtDelegatedCredentials:       "delegated_credentials",
	ExtSessionTicket:              "session_ticket",
	ExtPreSharedKey:               "pre_shared_key",
	ExtEarlyData:                  "early_data",
	ExtSupportedVersions:          "supported_versions",
	ExtCookie:                     "cookie",
	ExtPSKKeyExchangeModes:        "psk_key_exchange_modes",
	ExtCertificateAuthorities:     "certificate_authorities",
	ExtOIDFilters:                 "oid_filters",
	ExtPostHandshakeAuth:          "post_handshake_auth",
	ExtSignatureAlgorithmsCert:    "signature_algorithms_cert",
	ExtKeyShare:                   "key_share",
	ExtRenegotiationInfo:          "renegotiation_info",
	ExtEncryptedClientHello:       "encrypted_client_hello",
	ExtApplicationSettings:        "application_settings",
	ExtQUICTransportParameters:    "quic_transport_parameters",
}

// aliases maps common alternate spellings to canonical extension names.
var extensionAliases = map[string]string{
	"server_name_indication":                 "server_name",
	"sni":                                    "server_name",
	"elliptic_curves":                        "supported_groups",
	"supported_groups_ext":                   "supported_groups",
	"ec_point_formats":                       "ec_point_formats",
	"application_layer_protocol_negotiation": "application_layer_protocol_negotiation",
	"alpn":                                   "application_layer_protocol_negotiation",
	"signature_algorithms":                   "signature_algorithms",
	"supported_versions":                     "supported_versions",
	"application_settings":                   "application_settings",
	"alps":                                   "application_settings",
	"encrypted_client_hello":                 "encrypted_client_hello",
	"ech":                                    "encrypted_client_hello",
	"extended_master_secret":                 "extended_master_secret",
	"session_ticket":                         "session_ticket",
	"renegotiation_info":                     "renegotiation_info",
	"compress_certificate":                   "compress_certificate",
	"cert_compression":                       "compress_certificate",
	"record_size_limit":                      "record_size_limit",
	"delegated_credentials":                  "delegated_credentials",
	"psk_key_exchange_modes":                 "psk_key_exchange_modes",
	"signature_algorithms_cert":              "signature_algorithms_cert",
	"key_share":                              "key_share",
	"padding":                                "padding",
	"status_request":                         "status_request",
	"heartbeat":                              "heartbeat",
	"use_srtp":                               "use_srtp",
}

// ExtensionName returns the canonical name for an extension type id, or "" if
// the id is not registered. GREASE ids return "" (use IsGrease first).
func ExtensionName(id uint16) string {
	if IsGrease(id) {
		return ""
	}
	return extensionNames[id]
}

// ExtensionDisplay renders an id as its name when known, otherwise as hex.
func ExtensionDisplay(id uint16) string {
	if IsGrease(id) {
		return fmt.Sprintf("GREASE(0x%04x)", id)
	}
	if n := extensionNames[id]; n != "" {
		return n
	}
	return fmt.Sprintf("0x%04x", id)
}

// ParseExtension parses an extension name (case-insensitive, accepting the
// common aliases) into its numeric id. Numeric input is accepted both in
// decimal and 0x-prefixed hex. ok is false when the id is not registered.
func ParseExtension(s string) (id uint16, ok bool) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return 0, false
	}
	if v, valid := parseNumericID(t); valid {
		return v, true
	}
	if canon, ok := extensionAliases[t]; ok {
		t = canon
	}
	for id, name := range extensionNames {
		if name == t {
			return id, true
		}
	}
	return 0, false
}

// ExtensionNames returns a sorted copy of all known extension names.
func ExtensionNames() []string {
	out := make([]string, 0, len(extensionNames))
	for _, n := range extensionNames {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
