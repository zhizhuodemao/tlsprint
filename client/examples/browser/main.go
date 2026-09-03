// Command browser demonstrates the curl_cffi-style tlsprint client: pass the
// fingerprint directly on the call. It queries a public fingerprint service
// (tls.peet.ws) and prints the TLS and HTTP/2 fingerprints the server saw.
//
//	go run ./examples/browser -preset chrome-152
package main

import (
	"encoding/json"
	"flag"
	"fmt"

	tlsclient "github.com/lingulingo/tlsprint/client"
)

func main() {
	presetName := flag.String("preset", "chrome-152", "fingerprint preset name (e.g. chrome-152, firefox-145)")
	url := flag.String("url", "https://tls.peet.ws/api/all", "fingerprint endpoint")
	flag.Parse()

	// curl_cffi-style: impersonate is passed on the call.
	resp, err := tlsclient.Get(*url,
		tlsclient.Impersonate(*presetName),
		tlsclient.Header("Accept-Language", "zh-CN,zh;q=0.9"),
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("status: %d %s\nproto : %s\n\n", resp.StatusCode(), resp.Status(), resp.Proto())

	var out struct {
		HTTPVersion string `json:"http_version"`
		TLS         struct {
			JA3 string `json:"ja3"`
			JA4 string `json:"ja4"`
		} `json:"tls"`
		HTTP2 struct {
			AkamaiFingerprint string `json:"akamai_fingerprint"`
		} `json:"http2"`
	}
	if err := json.Unmarshal(resp.Body(), &out); err != nil {
		panic(err)
	}
	fmt.Println("TLS ja3   :", out.TLS.JA3)
	fmt.Println("TLS ja4   :", out.TLS.JA4)
	fmt.Println("HTTP/2    :", out.HTTPVersion)
	fmt.Println("akamai fp :", out.HTTP2.AkamaiFingerprint)
}
