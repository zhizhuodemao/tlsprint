package client_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	tlsclient "github.com/lingulingo/tlsprint/client"
)

// Example demonstrates the public client API: pick a preset, send a GET with
// query params and a header map, then POST a JSON body with result decoding.
// The example runs against a local test server so it is deterministic and
// works offline (in CI / godoc).
func Example() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"path":%q,"method":%q,"ua":%q,"body":%q}`,
			r.URL.Path, r.Method, r.Header.Get("User-Agent"), string(body))
	}))
	defer srv.Close()

	c := tlsclient.NewClient()
	if err := c.SetBrowser("chrome-152"); err != nil {
		panic(err)
	}

	// GET with query params and a header map (dictionary form).
	resp, err := c.R().
		SetQueryParam("q", "tls fingerprint").
		Get(srv.URL+"/check", map[string]string{"X-Api-Key": "secret"})
	if err != nil {
		panic(err)
	}
	fmt.Println(resp.StatusCode(), resp.Proto())

	// POST a JSON body and auto-decode the 2xx response into a map.
	var result map[string]any
	_, err = c.R().
		SetBody(map[string]any{"name": "tlsprint"}).
		SetResult(&result).
		Post(srv.URL + "/echo")
	if err != nil {
		panic(err)
	}
	fmt.Println(result["method"], result["ua"], result["body"])

	// Output:
	// 200 HTTP/1.1
	// POST Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36 {"name":"tlsprint"}
}

// Example_browser shows the curl_cffi-style module-level API: pass the
// fingerprint and per-request options directly on the call.
func Example_browser() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"q":%q,"xkey":%q}`, r.URL.Query().Get("q"), r.Header.Get("X-Api-Key"))
	}))
	defer srv.Close()

	resp, err := tlsclient.Get(srv.URL+"/check",
		tlsclient.Impersonate("chrome-152"),
		tlsclient.Header("X-Api-Key", "secret"),
		tlsclient.Query("q", "tls fingerprint"))
	if err != nil {
		panic(err)
	}
	fmt.Println(resp.StatusCode(), resp.String())

	// Output:
	// 200 {"q":"tls fingerprint","xkey":"secret"}
}
