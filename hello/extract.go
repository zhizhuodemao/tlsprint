package hello

import (
	"fmt"

	"github.com/lingulingo/tlsprint"
	"github.com/lingulingo/tlsprint/iana"
)

// TLSProfile converts the wire ClientHello into the semantic TLS fingerprint
// model (tlsprint.TLSProfile).
//
// Profiles derived from real traffic keep every identifier exactly as it
// appeared on the wire, including actual GREASE values; profiles declared by
// presets usually carry GREASE-free lists. Both are valid uses of the model,
// and fingerprint string codecs (ja3/ja4) apply their own GREASE handling on
// top, so consumers see consistent results either way.
//
// Extension bodies that the model does not summarise (key shares, SNI, ...)
// are reflected only through their position in Extensions.
func (c *ClientHello) TLSProfile() (*tlsprint.TLSProfile, error) {
	p := &tlsprint.TLSProfile{
		CipherSuites: append([]uint16(nil), c.CipherSuites...),
	}
	for _, e := range c.Extensions {
		p.Extensions = append(p.Extensions, e.Type)
	}
	for _, e := range c.Extensions {
		switch e.Type {
		case iana.ExtSupportedGroups:
			v, err := DecodeSupportedGroups(e.Data)
			if err != nil {
				return nil, fmt.Errorf("supported_groups: %w", err)
			}
			p.SupportedGroups = v
		case iana.ExtECPointFormats:
			v, err := DecodeECPointFormats(e.Data)
			if err != nil {
				return nil, fmt.Errorf("ec_point_formats: %w", err)
			}
			p.ECFormats = v
		case iana.ExtSupportedVersions:
			v, err := DecodeSupportedVersions(e.Data)
			if err != nil {
				return nil, fmt.Errorf("supported_versions: %w", err)
			}
			p.SupportedVersions = v
		case iana.ExtSignatureAlgorithms:
			v, err := DecodeSignatureAlgorithms(e.Data)
			if err != nil {
				return nil, fmt.Errorf("signature_algorithms: %w", err)
			}
			p.SignatureAlgorithms = v
		case iana.ExtSignatureAlgorithmsCert:
			v, err := DecodeSignatureAlgorithms(e.Data)
			if err != nil {
				return nil, fmt.Errorf("signature_algorithms_cert: %w", err)
			}
			p.SignatureAlgorithmsCert = v
		case iana.ExtPSKKeyExchangeModes:
			v, err := DecodePSKModes(e.Data)
			if err != nil {
				return nil, fmt.Errorf("psk_key_exchange_modes: %w", err)
			}
			p.PSKKeyExchangeModes = v
		case iana.ExtCompressCertificate:
			v, err := DecodeCertCompression(e.Data)
			if err != nil {
				return nil, fmt.Errorf("compress_certificate: %w", err)
			}
			p.CertCompression = v
		case iana.ExtRecordSizeLimit:
			v, err := DecodeRecordSizeLimit(e.Data)
			if err != nil {
				return nil, fmt.Errorf("record_size_limit: %w", err)
			}
			p.RecordSizeLimit = v
		case iana.ExtDelegatedCredentials:
			v, err := DecodeDelegatedCredentials(e.Data)
			if err != nil {
				return nil, fmt.Errorf("delegated_credentials: %w", err)
			}
			p.DelegatedCredentials = v
		}
	}
	return p, nil
}

// ToClientHello assembles a wire ClientHello whose structural identifier
// lists (ciphers, groups, versions, ...) come from the semantic profile.
//
// This is the inverse direction of TLSProfile and is primarily useful for
// tests and tooling: the returned message contains exactly the extensions the
// profile describes with empty bodies for those without dedicated payload
// fields, so it is NOT a complete, connectable ClientHello by itself —
// engines fill SNI, key shares and friends at dial time. The utls adapter
// (tlsprint/utls) is the production path from profile to connection.
func ToClientHello(p *tlsprint.TLSProfile) (*ClientHello, error) {
	if p == nil {
		return nil, fmt.Errorf("hello: nil profile")
	}
	legacy := p.LegacyVersion
	if legacy == 0 {
		legacy = iana.VersionTLS12
	}
	ch := &ClientHello{
		LegacyVersion:      legacy,
		CompressionMethods: []byte{0},
		CipherSuites:       append([]uint16(nil), p.CipherSuites...),
	}
	if len(ch.CipherSuites) == 0 {
		return nil, fmt.Errorf("hello: profile has no cipher suites")
	}
	for _, ext := range p.Extensions {
		ch.Extensions = append(ch.Extensions, Extension{Type: ext})
	}
	// Fill payloads only for extension slots the profile declared — never
	// invent extensions outside the declared order.
	setPayload := func(typ uint16, body []byte) {
		if len(body) == 0 {
			return // absent list → leave the type-only slot empty
		}
		for i := range ch.Extensions {
			if ch.Extensions[i].Type == typ {
				ch.Extensions[i].Data = body
				return
			}
		}
	}
	setPayload(iana.ExtSupportedGroups, EncodeSupportedGroups(p.SupportedGroups))
	setPayload(iana.ExtECPointFormats, EncodeECPointFormats(p.ECFormats))
	setPayload(iana.ExtSupportedVersions, EncodeSupportedVersions(p.SupportedVersions))
	setPayload(iana.ExtSignatureAlgorithms, EncodeSignatureAlgorithms(p.SignatureAlgorithms))
	setPayload(iana.ExtSignatureAlgorithmsCert, EncodeSignatureAlgorithms(p.SignatureAlgorithmsCert))
	setPayload(iana.ExtPSKKeyExchangeModes, EncodePSKModes(p.PSKKeyExchangeModes))
	return ch, nil
}
