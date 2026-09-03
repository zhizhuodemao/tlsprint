// Package iana provides identifier registries for the TLS extension and
// cryptographic identifiers that make up a ClientHello fingerprint, plus
// GREASE semantics as defined by RFC 8701.
//
// All registries are purely informational: fingerprints themselves are stored
// as plain uint16 lists, and these tables map ids to canonical names and back
// for display, tooling, and tests.
package iana

import (
	"crypto/rand"
	"fmt"
	"io"
)

// GreaseMarker is the placeholder value tlsprint uses to record a GREASE
// position inside an ordered identifier list. It is the smallest GREASE
// value (0x0a0a) and, following the ecosystem convention, is replaced with a
// concrete randomized GREASE value when a ClientHello is actually built.
const GreaseMarker uint16 = 0x0a0a

// greaseTable is the RFC 8701 GREASE value table.
var greaseTable = [...]uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

// IsGrease reports whether v is a GREASE value from the RFC 8701 table.
func IsGrease(v uint16) bool {
	if v&0x0f != 0x0a {
		return false
	}
	return v>>8 == v&0xff
}

// NextGrease returns a uniformly random GREASE value drawn from the RFC 8701
// table. It uses crypto/rand. rand may be nil, in which case crypto/rand.Reader
// is used; supply a deterministic source for reproducible builds and tests.
func NextGrease(rand io.Reader) (uint16, error) {
	if rand == nil {
		rand = randReader
	}
	var b [1]byte
	if _, err := io.ReadFull(rand, b[:]); err != nil {
		return 0, err
	}
	return greaseTable[int(b[0])&0x0f], nil
}

var randReader io.Reader = rand.Reader

// FormatID renders an identifier in a human-friendly way for a registry
// lookup failure: as a zero-padded hex value.
func FormatID(v uint16) string {
	return fmt.Sprintf("0x%04x", v)
}
