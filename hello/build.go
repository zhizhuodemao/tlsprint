package hello

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lingulingo/tlsprint/iana"
)

// MarshalBody serializes the ClientHello body: the message contents without
// any record or handshake framing (starts with the protocol version).
func (c *ClientHello) MarshalBody() ([]byte, error) {
	if len(c.Random) != 32 {
		return nil, errors.New("hello: random must be 32 bytes")
	}
	if len(c.SessionID) > 255 {
		return nil, errors.New("hello: session id too long")
	}
	if len(c.CipherSuites) == 0 {
		return nil, errors.New("hello: no cipher suites")
	}
	if len(c.CipherSuites) > 0x7fff {
		return nil, errors.New("hello: too many cipher suites")
	}
	if len(c.CompressionMethods) > 255 {
		return nil, errors.New("hello: too many compression methods")
	}
	if len(c.Extensions) > 0 && extBytesLen(c.Extensions) > 0xffff {
		return nil, errors.New("hello: extensions too large")
	}

	out := make([]byte, 0, 2+32+1+len(c.SessionID)+2+2*len(c.CipherSuites)+1+len(c.CompressionMethods)+2+extBytesLen(c.Extensions))
	out = binary.BigEndian.AppendUint16(out, c.LegacyVersion)
	out = append(out, c.Random[:]...)
	out = append(out, byte(len(c.SessionID)))
	out = append(out, c.SessionID...)
	out = binary.BigEndian.AppendUint16(out, uint16(2*len(c.CipherSuites)))
	for _, cs := range c.CipherSuites {
		out = binary.BigEndian.AppendUint16(out, cs)
	}
	out = append(out, byte(len(c.CompressionMethods)))
	out = append(out, c.CompressionMethods...)
	if len(c.Extensions) > 0 {
		out = binary.BigEndian.AppendUint16(out, uint16(extBytesLen(c.Extensions)))
		for _, e := range c.Extensions {
			out = binary.BigEndian.AppendUint16(out, e.Type)
			out = binary.BigEndian.AppendUint16(out, uint16(len(e.Data)))
			out = append(out, e.Data...)
		}
	}
	return out, nil
}

// MarshalHandshake serializes the ClientHello as a bare handshake message
// (handshake type byte + 3-byte length + body).
func (c *ClientHello) MarshalHandshake() ([]byte, error) {
	body, err := c.MarshalBody()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 4+len(body))
	out = append(out, handshakeTypeClientHello)
	out = append(out, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	out = append(out, body...)
	return out, nil
}

// MarshalRecord serializes the ClientHello as a TLS handshake record. The
// record-level version defaults to c.LegacyVersion when recordVersion is 0.
func (c *ClientHello) MarshalRecord(recordVersion uint16) ([]byte, error) {
	hs, err := c.MarshalHandshake()
	if err != nil {
		return nil, err
	}
	if len(hs) > maxRecordPlain {
		return nil, fmt.Errorf("hello: record too large (%d > %d)", len(hs), maxRecordPlain)
	}
	if recordVersion == 0 {
		recordVersion = c.LegacyVersion
	}
	out := make([]byte, 0, 5+len(hs))
	out = append(out, recordTypeHandshake)
	out = binary.BigEndian.AppendUint16(out, recordVersion)
	out = binary.BigEndian.AppendUint16(out, uint16(len(hs)))
	out = append(out, hs...)
	return out, nil
}

func extBytesLen(exts []Extension) int {
	n := 0
	for _, e := range exts {
		n += 4 + len(e.Data)
	}
	return n
}

// SetExtension replaces the first extension of the given type (or appends it
// when absent). It is a convenience for building ClientHellos from scratch.
func (c *ClientHello) SetExtension(typ uint16, data []byte) {
	for i := range c.Extensions {
		if c.Extensions[i].Type == typ {
			c.Extensions[i].Data = data
			return
		}
	}
	c.Extensions = append(c.Extensions, Extension{Type: typ, Data: data})
}

// RemoveExtensions drops all extensions of the given types.
func (c *ClientHello) RemoveExtensions(types ...uint16) {
	drop := make(map[uint16]bool, len(types))
	for _, t := range types {
		drop[t] = true
	}
	out := c.Extensions[:0]
	for _, e := range c.Extensions {
		if !drop[e.Type] {
			out = append(out, e)
		}
	}
	c.Extensions = out
}

// EnsureLegacyVersion normalises LegacyVersion to 0x0303 when zero (the value
// every modern TLS client sends).
func (c *ClientHello) EnsureLegacyVersion() {
	if c.LegacyVersion == 0 {
		c.LegacyVersion = iana.VersionTLS12
	}
}
