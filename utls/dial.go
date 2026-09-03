package utls

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"strings"

	"github.com/lingulingo/tlsprint/preset"
	utls "github.com/refraction-networking/utls"
)

// DialOptions customises TLS dialing with a preset fingerprint.
type DialOptions struct {
	// Spec overrides the profile→ClientHelloSpec conversion options. When
	// nil, NewOptions(profile) defaults apply (Chromium-style GREASE unless
	// the profile disables it, ALPN h2+http/1.1 or http/1.1).
	Spec *Options

	// ServerName sets the SNI and certificate verification name. When empty
	// it defaults to the host part of the dial address.
	ServerName string

	// InsecureSkipVerify disables server certificate verification
	// (TLS fingerprint testing only — never enable in production).
	InsecureSkipVerify bool

	// RootCAs overrides the trusted root pool used for certificate
	// verification.
	RootCAs *x509.CertPool

	// NetDial overrides the underlying TCP dialer, e.g. for proxies.
	NetDial func(ctx context.Context, network, address string) (net.Conn, error)
}

// Dial establishes a TLS connection whose ClientHello fingerprints match the
// given preset. The returned *utls.UConn has completed the handshake and is
// ready to use; it is a plain net.Conn so it works with any protocol stack on
// top (HTTP/1.1, custom HTTP/2, raw protocols).
//
// Example:
//
//	conn, err := utls.Dial(ctx, "tcp", "example.com:443",
//	    preset.MustBuiltin().Lookup("chrome-141"), nil)
//	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
//
// The preset profile determines the cipher list, extension order, supported
// groups, signature algorithms and GREASE placement of the ClientHello. The
// negotiated protocol (ALPN) depends on Spec.ALPN and what the server offers.
func Dial(ctx context.Context, network, address string, p *preset.Preset, opts *DialOptions) (*utls.UConn, error) {
	if p == nil {
		return nil, fmt.Errorf("utls: nil preset")
	}
	dopts := opts
	if dopts == nil {
		dopts = &DialOptions{}
	}

	specOpts := dopts.Spec
	if specOpts == nil {
		specOpts = NewOptions(&p.Profile)
	}
	spec, err := FromProfile(&p.TLS, specOpts)
	if err != nil {
		return nil, err
	}

	if network == "" {
		network = "tcp"
	}
	host, err := dialHost(address)
	if err != nil {
		return nil, err
	}

	serverName := dopts.ServerName
	if serverName == "" {
		serverName = host
	}
	config := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: dopts.InsecureSkipVerify,
		RootCAs:            dopts.RootCAs,
		NextProtos:         append([]string(nil), specOpts.ALPN...),
	}

	raw, err := dial(ctx, network, address, dopts.NetDial)
	if err != nil {
		return nil, fmt.Errorf("utls: dial %s: %w", address, err)
	}

	uconn := utls.UClient(raw, config, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		raw.Close()
		return nil, fmt.Errorf("utls: apply preset: %w", err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("utls: handshake %s: %w", address, err)
	}
	return uconn, nil
}

// DialByName is Dial with a preset resolved by name from the built-in
// registry (see preset.Registry.Lookup for accepted names, e.g. "chrome-141"
// or "chrome").
func DialByName(ctx context.Context, network, address, presetName string, opts *DialOptions) (*utls.UConn, error) {
	p := preset.MustBuiltin().Lookup(presetName)
	if p == nil {
		return nil, fmt.Errorf("utls: unknown preset %q", presetName)
	}
	return Dial(ctx, network, address, p, opts)
}

// dialHost extracts the host part of an address. Addresses without a port are
// returned unchanged (the caller's address is used verbatim for dialing).
func dialHost(address string) (string, error) {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return strings.Trim(host, "[]"), nil
	}
	if strings.Contains(err.Error(), "missing port") {
		return strings.Trim(address, "[]"), nil
	}
	return "", fmt.Errorf("utls: bad address %q: %w", address, err)
}

func dial(ctx context.Context, network, address string, netDial func(ctx context.Context, network, address string) (net.Conn, error)) (net.Conn, error) {
	if netDial != nil {
		return netDial(ctx, network, address)
	}
	d := &net.Dialer{}
	return d.DialContext(ctx, network, address)
}
