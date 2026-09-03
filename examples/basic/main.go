// Command basic demonstrates the core tlsprint API: loading the curated
// fingerprint registry, inspecting a preset, deriving its canonical JA3 and
// parsing a captured ClientHello from hex.
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/lingulingo/tlsprint/hello"
	"github.com/lingulingo/tlsprint/ja3"
	"github.com/lingulingo/tlsprint/ja4"
	"github.com/lingulingo/tlsprint/preset"
)

func main() {
	reg := preset.MustBuiltin()

	// 1. Look up a curated client fingerprint by name or product.
	chrome := reg.Lookup("chrome-141")
	if chrome == nil {
		panic("chrome preset not found")
	}
	fmt.Printf("preset: %s (%s %s)\n", chrome.Key, chrome.Product, chrome.Version)
	fmt.Printf("user-agent: %s\n", chrome.UserAgent())
	fmt.Printf("cipher suites: %d, extensions: %d\n",
		len(chrome.TLS.CipherSuites), len(chrome.TLS.Extensions))

	// 2. Derive the canonical JA3 string (and md5) from the profile lists.
	ja3s := ja3.FromProfile(&chrome.TLS)
	fmt.Printf("ja3:     %s\n", ja3s)
	fmt.Printf("ja3_md5: %s\n", ja3.Hash(ja3s))

	// 3. Parse a captured ClientHello (full TLS record) from hex and compute
	//    both fingerprints from the wire bytes. The example below is a
	//    minimal TLS 1.3 ClientHello skeleton.
	raw, _ := hex.DecodeString(hexDump(minimalHello()))
	ch, err := hello.Parse(raw)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nparsed ClientHello: version %#x, %d ciphers, %d extensions\n",
		ch.LegacyVersion, len(ch.CipherSuites), len(ch.Extensions))
	fmt.Printf("ja3: %s\n", ja3.Compute(ch))
	j4, err := ja4.Compute(ch)
	if err != nil {
		panic(err)
	}
	fmt.Printf("ja4: %s\n", j4)
}

// minimalHello returns bytes of a hand-built ClientHello (see the hello
// package for programmatic construction; this shows raw-byte input).
func minimalHello() []byte {
	ch := &hello.ClientHello{
		LegacyVersion:      0x0303,
		CompressionMethods: []byte{0},
		CipherSuites:       []uint16{0x1301, 0x1302, 0x1303},
		Extensions: []hello.Extension{
			{Type: 0x0000, Data: []byte{0, 14, 0, 0, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}},
			{Type: 0x0010, Data: hello.EncodeALPN([]string{"h2"})},
			{Type: 0x002b, Data: hello.EncodeSupportedVersions([]uint16{0x0304, 0x0303})},
			{Type: 0x000a, Data: hello.EncodeSupportedGroups([]uint16{29, 23, 24})},
			{Type: 0x000d, Data: hello.EncodeSignatureAlgorithms([]uint16{0x0403, 0x0804, 0x0401})},
		},
	}
	rec, err := ch.MarshalRecord(0)
	if err != nil {
		panic(err)
	}
	return rec
}

func hexDump(b []byte) string {
	return hex.EncodeToString(b)
}
