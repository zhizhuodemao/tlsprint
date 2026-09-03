package hello

import (
	"encoding/binary"
	"fmt"
)

// KeyShare is one entry of the key_share extension (RFC 8446 §4.2.8).
type KeyShare struct {
	Group uint16
	Data  []byte
}

// Decode helpers parse the bodies of well-known extensions. They are kept
// strict: a malformed body is an error, never silently truncated data.

// DecodeSNI parses the server_name extension body and returns the first
// host_name entry.
func DecodeSNI(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("%w: server_name list length", ErrShortData)
	}
	list := data[2:]
	if len(data)-2 != int(binary.BigEndian.Uint16(data[:2])) {
		return "", ErrMalformed
	}
	for len(list) > 0 {
		if len(list) < 3 {
			return "", fmt.Errorf("%w: server_name entry", ErrMalformed)
		}
		nameType := list[0]
		n := int(binary.BigEndian.Uint16(list[1:3]))
		list = list[3:]
		if n > len(list) {
			return "", fmt.Errorf("%w: server_name length", ErrShortData)
		}
		host := string(list[:n])
		list = list[n:]
		if nameType == 0 { // host_name
			return host, nil
		}
	}
	return "", nil
}

// DecodeALPN parses the ALPN extension body and returns the offered
// protocols in order.
func DecodeALPN(data []byte) ([]string, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("%w: alpn list length", ErrShortData)
	}
	rest := data[2:]
	if len(data)-2 != int(binary.BigEndian.Uint16(data[:2])) {
		return nil, ErrMalformed
	}
	var out []string
	for len(rest) > 0 {
		n := int(rest[0])
		rest = rest[1:]
		if n > len(rest) {
			return nil, fmt.Errorf("%w: alpn protocol length", ErrShortData)
		}
		out = append(out, string(rest[:n]))
		rest = rest[n:]
	}
	return out, nil
}

// DecodeSupportedGroups parses the supported_groups (elliptic_curves)
// extension body into the ordered group list.
func DecodeSupportedGroups(data []byte) ([]uint16, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("%w: groups length", ErrShortData)
	}
	n := int(binary.BigEndian.Uint16(data[:2]))
	if n%2 != 0 || 2+n > len(data) {
		return nil, ErrMalformed
	}
	out := make([]uint16, n/2)
	for i := range out {
		out[i] = binary.BigEndian.Uint16(data[2+2*i:])
	}
	return out, nil
}

// DecodeECPointFormats parses the ec_point_formats extension body.
func DecodeECPointFormats(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("%w: point formats length", ErrShortData)
	}
	n := int(data[0])
	if 1+n > len(data) {
		return nil, ErrShortData
	}
	out := make([]byte, n)
	copy(out, data[1:1+n])
	return out, nil
}

// DecodeSupportedVersions parses the supported_versions extension body.
func DecodeSupportedVersions(data []byte) ([]uint16, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("%w: versions length", ErrShortData)
	}
	n := int(data[0])
	if n%2 != 0 || 1+n > len(data) {
		return nil, ErrMalformed
	}
	out := make([]uint16, n/2)
	for i := range out {
		out[i] = binary.BigEndian.Uint16(data[1+2*i:])
	}
	return out, nil
}

// DecodeSignatureAlgorithms parses a signature_algorithms or
// signature_algorithms_cert extension body.
func DecodeSignatureAlgorithms(data []byte) ([]uint16, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("%w: sigalgs length", ErrShortData)
	}
	n := int(binary.BigEndian.Uint16(data[:2]))
	if n%2 != 0 || 2+n > len(data) {
		return nil, ErrMalformed
	}
	out := make([]uint16, n/2)
	for i := range out {
		out[i] = binary.BigEndian.Uint16(data[2+2*i:])
	}
	return out, nil
}

// DecodePSKModes parses the psk_key_exchange_modes extension body.
func DecodePSKModes(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("%w: psk modes length", ErrShortData)
	}
	n := int(data[0])
	if 1+n > len(data) {
		return nil, ErrShortData
	}
	out := make([]byte, n)
	copy(out, data[1:1+n])
	return out, nil
}

// DecodeCertCompression parses the compress_certificate extension body.
func DecodeCertCompression(data []byte) ([]uint16, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("%w: cert compression length", ErrShortData)
	}
	n := int(binary.BigEndian.Uint16(data[:2]))
	if n%2 != 0 || 2+n > len(data) {
		return nil, ErrMalformed
	}
	out := make([]uint16, n/2)
	for i := range out {
		out[i] = binary.BigEndian.Uint16(data[2+2*i:])
	}
	return out, nil
}

// DecodeRecordSizeLimit parses the record_size_limit extension body.
func DecodeRecordSizeLimit(data []byte) (uint16, error) {
	if len(data) != 2 {
		return 0, ErrMalformed
	}
	return binary.BigEndian.Uint16(data), nil
}

// DecodeDelegatedCredentials parses the delegated_credentials extension body.
func DecodeDelegatedCredentials(data []byte) ([]uint16, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("%w: delegated credentials length", ErrShortData)
	}
	n := int(binary.BigEndian.Uint16(data[:2]))
	if n%2 != 0 || 2+n > len(data) {
		return nil, ErrMalformed
	}
	out := make([]uint16, n/2)
	for i := range out {
		out[i] = binary.BigEndian.Uint16(data[2+2*i:])
	}
	return out, nil
}

// DecodeKeyShares parses the key_share extension body into its ordered
// (group, key exchange data) entries.
func DecodeKeyShares(data []byte) ([]KeyShare, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("%w: keyshare length", ErrShortData)
	}
	rest := data[2:]
	if len(data)-2 != int(binary.BigEndian.Uint16(data[:2])) {
		return nil, ErrMalformed
	}
	var out []KeyShare
	for len(rest) > 0 {
		if len(rest) < 4 {
			return nil, fmt.Errorf("%w: keyshare entry", ErrShortData)
		}
		group := binary.BigEndian.Uint16(rest[:2])
		n := int(binary.BigEndian.Uint16(rest[2:4]))
		rest = rest[4:]
		if n > len(rest) {
			return nil, fmt.Errorf("%w: keyshare data", ErrShortData)
		}
		out = append(out, KeyShare{Group: group, Data: rest[:n:n]})
		rest = rest[n:]
	}
	return out, nil
}

// Encode helpers build extension bodies; they are the inverse of the Decode
// helpers above.

// EncodeALPN builds an ALPN extension body from the ordered protocol list.
func EncodeALPN(protocols []string) []byte {
	size := 0
	for _, p := range protocols {
		size += 1 + len(p)
	}
	out := make([]byte, 0, 2+size)
	out = binary.BigEndian.AppendUint16(out, uint16(size))
	for _, p := range protocols {
		out = append(out, byte(len(p)))
		out = append(out, p...)
	}
	return out
}

// EncodeSupportedGroups builds a supported_groups extension body.
func EncodeSupportedGroups(groups []uint16) []byte {
	out := make([]byte, 0, 2+2*len(groups))
	out = binary.BigEndian.AppendUint16(out, uint16(2*len(groups)))
	for _, g := range groups {
		out = binary.BigEndian.AppendUint16(out, g)
	}
	return out
}

// EncodeECPointFormats builds an ec_point_formats extension body.
func EncodeECPointFormats(formats []byte) []byte {
	out := make([]byte, 0, 1+len(formats))
	out = append(out, byte(len(formats)))
	out = append(out, formats...)
	return out
}

// EncodeSupportedVersions builds a supported_versions extension body.
func EncodeSupportedVersions(versions []uint16) []byte {
	out := make([]byte, 0, 1+2*len(versions))
	out = append(out, byte(2*len(versions)))
	for _, v := range versions {
		out = binary.BigEndian.AppendUint16(out, v)
	}
	return out
}

// EncodeSignatureAlgorithms builds a signature_algorithms extension body.
func EncodeSignatureAlgorithms(algs []uint16) []byte {
	out := make([]byte, 0, 2+2*len(algs))
	out = binary.BigEndian.AppendUint16(out, uint16(2*len(algs)))
	for _, a := range algs {
		out = binary.BigEndian.AppendUint16(out, a)
	}
	return out
}

// EncodePSKModes builds a psk_key_exchange_modes extension body.
func EncodePSKModes(modes []byte) []byte {
	out := make([]byte, 0, 1+len(modes))
	out = append(out, byte(len(modes)))
	out = append(out, modes...)
	return out
}
