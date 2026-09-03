package hello

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lingulingo/tlsprint/iana"
)

// Errors returned by the parsers. All are wrapped with position context;
// use errors.Is for classification.
var (
	ErrShortData        = errors.New("hello: truncated data")
	ErrBadRecordType    = errors.New("hello: not a handshake record")
	ErrBadHandshakeType = errors.New("hello: not a client hello handshake")
	ErrMalformed        = errors.New("hello: malformed client hello")
)

// Parse parses ClientHello bytes, auto-detecting the framing:
//
//   - a full TLS record (first byte 0x14–0x17: change_cipher_spec, alert,
//     handshake or application_data);
//   - a bare handshake message (first byte 0x01, client_hello);
//   - a bare ClientHello body (starts with the protocol version, e.g. 0x0303).
//
// Record and handshake headers are not retained; use ParseRecord if you need
// the record-level version.
func Parse(data []byte) (*ClientHello, error) {
	if len(data) == 0 {
		return nil, ErrShortData
	}
	switch data[0] {
	case recordTypeHandshake:
		ch, _, err := ParseRecord(data)
		return ch, err
	case 0x14, 0x15, 0x17: // other TLS content types are never ClientHellos
		_, _, err := ParseRecord(data)
		return nil, err
	case handshakeTypeClientHello:
		ch, _, err := ParseHandshake(data)
		return ch, err
	default:
		// A ClientHello body always starts with the legacy version (0x03 0x03).
		// Distinguish "bare handshake of another type" (whose 3-byte length
		// matches the remaining payload) from a body by that length check.
		if looksLikeHandshake(data) {
			_, _, err := ParseHandshake(data)
			return nil, err
		}
		return ParseBody(data)
	}
}

// looksLikeHandshake reports whether data plausibly is a bare handshake
// message of some type other than client_hello: first byte in the handshake
// type range and an embedded 3-byte length matching the payload.
func looksLikeHandshake(data []byte) bool {
	if len(data) < 4 || data[0] > 0x1f {
		return false
	}
	length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	return length == len(data)-4
}

// ParseRecord parses one full TLS record containing a ClientHello handshake
// message. It returns the message and the record-level version.
func ParseRecord(data []byte) (*ClientHello, uint16, error) {
	if len(data) < 5 {
		return nil, 0, fmt.Errorf("%w: record header", ErrShortData)
	}
	if data[0] != recordTypeHandshake {
		return nil, 0, ErrBadRecordType
	}
	version := binary.BigEndian.Uint16(data[1:3])
	length := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+length {
		return nil, 0, fmt.Errorf("%w: record body %d/%d", ErrShortData, len(data)-5, length)
	}
	ch, _, err := ParseHandshake(data[5 : 5+length])
	return ch, version, err
}

// ParseHandshake parses a bare handshake message whose first byte is the
// client_hello handshake type. Returns the message and the total handshake
// body length.
func ParseHandshake(data []byte) (*ClientHello, int, error) {
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("%w: handshake header", ErrShortData)
	}
	if data[0] != handshakeTypeClientHello {
		return nil, 0, ErrBadHandshakeType
	}
	length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+length {
		return nil, 0, fmt.Errorf("%w: handshake body %d/%d", ErrShortData, len(data)-4, length)
	}
	ch, err := ParseBody(data[4 : 4+length])
	return ch, length, err
}

// ParseBody parses a ClientHello body that starts directly with the protocol
// version field (no record/handshake framing).
func ParseBody(body []byte) (*ClientHello, error) {
	if len(body) < 2+32 {
		return nil, fmt.Errorf("%w: body too short", ErrShortData)
	}
	ch := &ClientHello{LegacyVersion: binary.BigEndian.Uint16(body[0:2])}
	copy(ch.Random[:], body[2:34])
	rest := body[34:]

	// Session id.
	sidLen, err := takeU8(&rest)
	if err != nil {
		return nil, fmt.Errorf("session id: %w", err)
	}
	ch.SessionID, err = takeBytes(&rest, int(sidLen))
	if err != nil {
		return nil, fmt.Errorf("session id: %w", err)
	}

	// Cipher suites.
	csLen, err := takeU16(&rest)
	if err != nil {
		return nil, fmt.Errorf("cipher suites length: %w", err)
	}
	if csLen%2 != 0 {
		return nil, fmt.Errorf("%w: cipher suites length %d is odd", ErrMalformed, csLen)
	}
	rawCS, err := takeBytes(&rest, int(csLen))
	if err != nil {
		return nil, fmt.Errorf("cipher suites: %w", err)
	}
	ch.CipherSuites = make([]uint16, csLen/2)
	for i := range ch.CipherSuites {
		ch.CipherSuites[i] = binary.BigEndian.Uint16(rawCS[2*i : 2*i+2])
	}

	// Compression methods.
	cmLen, err := takeU8(&rest)
	if err != nil {
		return nil, fmt.Errorf("compression methods length: %w", err)
	}
	ch.CompressionMethods, err = takeBytes(&rest, int(cmLen))
	if err != nil {
		return nil, fmt.Errorf("compression methods: %w", err)
	}

	// Extensions (optional in TLS 1.0, mandatory for TLS 1.2+ clients).
	if len(rest) == 0 {
		return ch, nil
	}
	extLen, err := takeU16(&rest)
	if err != nil {
		return nil, fmt.Errorf("extensions length: %w", err)
	}
	rawExt, err := takeBytes(&rest, int(extLen))
	if err != nil {
		return nil, fmt.Errorf("extensions: %w", err)
	}
	for len(rawExt) > 0 {
		if len(rawExt) < 4 {
			return nil, fmt.Errorf("%w: extension header at %d bytes left", ErrMalformed, len(rawExt))
		}
		typ := binary.BigEndian.Uint16(rawExt[0:2])
		el := int(binary.BigEndian.Uint16(rawExt[2:4]))
		rawExt = rawExt[4:]
		body, err := takeBytes(&rawExt, el)
		if err != nil {
			return nil, fmt.Errorf("extension %s: %w", iana.FormatID(typ), err)
		}
		ch.Extensions = append(ch.Extensions, Extension{Type: typ, Data: body})
	}
	return ch, nil
}

func takeU8(b *[]byte) (uint8, error) {
	if len(*b) < 1 {
		return 0, ErrShortData
	}
	v := (*b)[0]
	*b = (*b)[1:]
	return v, nil
}

func takeU16(b *[]byte) (uint16, error) {
	if len(*b) < 2 {
		return 0, ErrShortData
	}
	v := binary.BigEndian.Uint16((*b)[:2])
	*b = (*b)[2:]
	return v, nil
}

func takeBytes(b *[]byte, n int) ([]byte, error) {
	if n < 0 || len(*b) < n {
		return nil, ErrShortData
	}
	v := (*b)[:n:n]
	*b = (*b)[n:]
	return v, nil
}
