// Package hello implements wire-level parsing and construction of the TLS
// ClientHello message: the first handshake message a TLS client sends and the
// exact bytes that define its TLS fingerprint.
//
// The package is deliberately engine-independent: it works on plain bytes and
// keeps every extension body opaque ([]byte) so that unknown or exotic
// extensions survive a parse→build round trip untouched. Convenience decoders
// for the well-known extensions are provided for fingerprint analysis.
package hello

import (
	"github.com/lingulingo/tlsprint/iana"
)

// Record and handshake framing constants.
const (
	recordTypeHandshake = 0x16

	handshakeTypeClientHello = 0x01

	// maxRecordPlain is the maximum plaintext size of a TLS record.
	maxRecordPlain = 1 << 14
)

// Extension is one TLS extension as it appears on the wire: a type id and an
// opaque body. The body is preserved byte-for-byte between parse and build.
type Extension struct {
	Type uint16
	Data []byte
}

// ClientHello is a decoded ClientHello handshake message.
type ClientHello struct {
	// LegacyVersion is the protocol version in the ClientHello body
	// (RFC 8446 §4.1.2, always 0x0303 in TLS 1.3 era clients).
	LegacyVersion uint16

	// Random is the 32-byte client random.
	Random [32]byte

	// SessionID is the (possibly empty) legacy session id.
	SessionID []byte

	// CipherSuites is the ordered list of offered cipher suites, exactly as
	// it appears on the wire (GREASE values included when present).
	CipherSuites []uint16

	// CompressionMethods is the ordered compression method list (normally
	// {0}).
	CompressionMethods []byte

	// Extensions is the ordered extension list as it appears on the wire.
	Extensions []Extension
}

// FindExtension returns the first extension of the given type and whether it
// was found.
func (c *ClientHello) FindExtension(typ uint16) (Extension, bool) {
	for _, e := range c.Extensions {
		if e.Type == typ {
			return e, true
		}
	}
	return Extension{}, false
}

// GreaseCount returns the number of GREASE values present in the cipher
// suite list and extension list.
func (c *ClientHello) GreaseCount() int {
	n := 0
	for _, cs := range c.CipherSuites {
		if iana.IsGrease(cs) {
			n++
		}
	}
	for _, e := range c.Extensions {
		if iana.IsGrease(e.Type) {
			n++
		}
	}
	return n
}
