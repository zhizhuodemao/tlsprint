package tlsprint_test

import (
	"fmt"

	"github.com/lingulingo/tlsprint"
	"github.com/lingulingo/tlsprint/ja3"
	"github.com/lingulingo/tlsprint/preset"
)

// Example shows the typical flow: pick a curated preset, then derive its
// canonical JA3 fingerprint, and validate a hand-modified profile.
func Example() {
	reg, err := preset.Builtin()
	if err != nil {
		panic(err)
	}
	chrome := reg.Lookup("chrome-141")
	fmt.Println(chrome.Product, chrome.Version, chrome.UserAgent())

	ja3s := ja3.FromProfile(&chrome.TLS)
	fmt.Println(ja3s)

	// Profiles are plain data: JSON round-trip and validation come for free.
	p := &tlsprint.Profile{
		TLS: tlsprint.TLSProfile{
			CipherSuites: []uint16{0x1301, 0x1302, 0x1303},
			Extensions:   []uint16{0x0000, 0x002b, 0x000d},
		},
	}
	fmt.Println(p.Validate() == nil)

	// Output:
	// chrome 141 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
	// 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-10-23-35-27-16-18-13-17613-65037-11-51-65281-5-0-43-41,4588-29-23-24,0
	// true
}
