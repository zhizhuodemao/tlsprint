package client

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// handler is a small echo server used by the tests.
func handler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/check":
		// Report what the client sent: UA, query, cookies.
		out := map[string]any{
			"method": r.Method,
			"ua":     r.Header.Get("User-Agent"),
			"path":   r.URL.Path,
			"query":  r.URL.RawQuery,
		}
		if c, err := r.Cookie("sid"); err == nil {
			out["cookie"] = c.Value
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	case "/echo":
		body, _ := io.ReadAll(r.Body)
		out := map[string]any{
			"method": r.Method,
			"type":   r.Header.Get("Content-Type"),
			"body":   string(body),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	case "/set-cookie":
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc123", Path: "/"})
		fmt.Fprint(w, "ok")
	case "/redirect":
		http.Redirect(w, r, "/check", http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

func startTLSServer(t *testing.T, h2 bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(handler))
	srv.EnableHTTP2 = h2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func rootsOf(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

func TestClientGetOverHTTP2(t *testing.T) {
	srv := startTLSServer(t, true)
	c := NewClient(WithRootCAs(rootsOf(t, srv)))
	c.SetBrowser("chrome-141")

	resp, err := c.R().SetQueryParam("q", "hello world").
		SetQueryParam("n", "1").Get(srv.URL + "/check")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Proto() != "HTTP/2.0" {
		t.Fatalf("proto = %q, want HTTP/2.0", resp.Proto())
	}
	if !resp.IsSuccess() || resp.StatusCode() != 200 {
		t.Fatalf("status = %d", resp.StatusCode())
	}
	var got map[string]any
	if err := resp.JSON(&got); err != nil {
		t.Fatal(err)
	}
	if got["ua"] == "" || !strings.Contains(got["ua"].(string), "Chrome/141") {
		t.Fatalf("ua = %v", got["ua"])
	}
	if got["query"] != "n=1&q=hello+world" {
		t.Fatalf("query = %v", got["query"])
	}
}

func TestClientFallbackToHTTP1(t *testing.T) {
	// HTTP/1.1-only server: the auto transport must fall back cleanly.
	srv := startTLSServer(t, false)
	c := NewClient(WithRootCAs(rootsOf(t, srv)))

	resp, err := c.R().Get(srv.URL + "/check")
	if err != nil {
		t.Fatalf("Get over h1-only server: %v", err)
	}
	if resp.Proto() != "HTTP/1.1" {
		t.Fatalf("proto = %q, want HTTP/1.1", resp.Proto())
	}
	if !resp.IsSuccess() {
		t.Fatalf("status = %d", resp.StatusCode())
	}
}

func TestClientForceHTTP1(t *testing.T) {
	srv := startTLSServer(t, true) // server supports h2, client insists on h1
	c := NewClient(WithRootCAs(rootsOf(t, srv)))
	c.ForceHTTP1()

	resp, err := c.R().Get(srv.URL + "/check")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Proto() != "HTTP/1.1" {
		t.Fatalf("proto = %q, want HTTP/1.1", resp.Proto())
	}
}

func TestClientPostJSON(t *testing.T) {
	srv := startTLSServer(t, true)
	c := NewClient(WithRootCAs(rootsOf(t, srv)))
	c.SetBrowser("firefox-145")

	body := map[string]any{"name": "tlsprint", "n": 42}
	resp, err := c.R().SetBody(body).Post(srv.URL + "/echo")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Method string `json:"method"`
		Type   string `json:"type"`
		Body   string `json:"body"`
	}
	if err := resp.JSON(&got); err != nil {
		t.Fatal(err)
	}
	if got.Method != "POST" {
		t.Fatalf("method = %s", got.Method)
	}
	if got.Type != "application/json" {
		t.Fatalf("content-type = %q", got.Type)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(got.Body), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["name"] != "tlsprint" || decoded["n"] != float64(42) {
		t.Fatalf("decoded = %v", decoded)
	}
}

func TestClientFormAndRedirect(t *testing.T) {
	srv := startTLSServer(t, true)
	c := NewClient(WithRootCAs(rootsOf(t, srv)))

	resp, err := c.R().SetFormData(map[string]string{"a": "1", "b": "2"}).Post(srv.URL + "/echo")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := resp.JSON(&got); err != nil {
		t.Fatal(err)
	}
	if got["type"] != "application/x-www-form-urlencoded" {
		t.Fatalf("type = %v", got["type"])
	}

	// Redirects are followed by default.
	resp, err = c.R().Get(srv.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	if resp.RequestURL() != srv.URL+"/check" {
		t.Fatalf("final url = %q", resp.RequestURL())
	}

	// ... and can be disabled.
	c.SetRedirects(0)
	resp, err = c.R().Get(srv.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode())
	}
}

func TestClientCookieJar(t *testing.T) {
	srv := startTLSServer(t, true)
	c := NewClient(WithRootCAs(rootsOf(t, srv)))
	c.EnableCookieJar()

	if _, err := c.R().Get(srv.URL + "/set-cookie"); err != nil {
		t.Fatal(err)
	}
	resp, err := c.R().Get(srv.URL + "/check")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := resp.JSON(&got); err != nil {
		t.Fatal(err)
	}
	if got["cookie"] != "abc123" {
		t.Fatalf("cookie = %v", got["cookie"])
	}
}

func TestClientResultDecode(t *testing.T) {
	srv := startTLSServer(t, false)
	c := NewClient(WithRootCAs(rootsOf(t, srv)))

	var out struct {
		Method string `json:"method"`
	}
	resp, err := c.R().SetResult(&out).Get(srv.URL + "/check")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("status %d", resp.StatusCode())
	}
	if out.Method != "GET" {
		t.Fatalf("decoded result method = %q", out.Method)
	}
}

// TestClientGetWithHeaderMap verifies that headers can be passed as a map
// directly in the verb call.
func TestClientGetWithHeaderMap(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"one": r.Header.Get("X-Custom-One"),
			"two": r.Header.Get("X-Custom-Two"),
		})
	})
	srv := httptest.NewUnstartedServer(h)
	srv.StartTLS()
	defer srv.Close()
	c := NewClient(WithRootCAs(rootsOf(t, srv)))

	var got map[string]string
	resp, err := c.R().
		SetResult(&got).
		Get(srv.URL+"/", map[string]string{
			"X-Custom-One": "one-value",
			"X-Custom-Two": "two-value",
		})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("status %d", resp.StatusCode())
	}
	if got["one"] != "one-value" || got["two"] != "two-value" {
		t.Fatalf("headers echoed = %v", got)
	}
}

// TestClientConcurrentSetBaseURL exercises concurrent SetBaseURL + requests to
// catch data races on baseURL (it is snapshotted into each Request).
func TestClientConcurrentSetBaseURL(t *testing.T) {
	srv := startTLSServer(t, false)
	c := NewClient(WithRootCAs(rootsOf(t, srv)))
	c.SetBaseURL(srv.URL)
	c.SetRedirects(0)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = c.R().Get("/check")
		}()
		go func() {
			defer wg.Done()
			_ = c.SetBaseURL(srv.URL)
		}()
	}
	wg.Wait()
}
