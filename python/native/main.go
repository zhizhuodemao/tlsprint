package main

/*
#include <stdint.h>
#include <stdlib.h>
typedef struct {
    void *metadata;
    size_t metadata_len;
    void *body;
    size_t body_len;
} tlsprint_result;
*/
import "C"

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/lingulingo/tlsprint/client"
	"github.com/lingulingo/tlsprint/preset"
)

type session struct {
	client *client.Client
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	active sync.WaitGroup
}

var sessions = struct {
	sync.Mutex
	values map[uint64]*session
}{values: make(map[uint64]*session)}
var nextID atomic.Uint64

type options struct {
	Impersonate string `json:"impersonate"`
	Proxy       string `json:"proxy"`
	Verify      bool   `json:"verify"`
	CAFile      string `json:"ca_file"`
	Protocol    string `json:"protocol"`
	Redirects   bool   `json:"redirects"`
	Cookies     bool   `json:"cookies"`
}

type request struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Timeout float64           `json:"timeout"`
	HasBody bool              `json:"has_body"`
}

type command struct {
	Op        string  `json:"op"`
	SessionID uint64  `json:"session_id"`
	Name      string  `json:"name"`
	Product   string  `json:"product"`
	Options   options `json:"options"`
	Request   request `json:"request"`
}

type apiError struct {
	Kind    string `json:"type"`
	Message string `json:"message"`
}

func (e *apiError) Error() string  { return e.Message }
func invalid(message string) error { return &apiError{"InvalidArgument", message} }

func createSession(o options) (any, []byte, error) {
	reg, err := preset.Builtin()
	if err != nil {
		return nil, nil, err
	}
	p := reg.Lookup(o.Impersonate)
	if p == nil {
		return nil, nil, invalid("unknown preset: " + o.Impersonate)
	}
	if o.Protocol != "auto" && o.Protocol != "h1" && o.Protocol != "h2" {
		return nil, nil, invalid("protocol must be auto, h1, or h2")
	}
	var proxy string
	if o.Proxy != "" {
		u, err := url.Parse(o.Proxy)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, nil, invalid("proxy must be an http:// or https:// URL with a host")
		}
		if u.Port() == "" {
			port := "80"
			if u.Scheme == "https" {
				port = "443"
			}
			u.Host = net.JoinHostPort(u.Hostname(), port)
		}
		proxy = u.String()
	}
	var roots *x509.CertPool
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, nil, invalid("cannot read CA file: " + err.Error())
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, nil, invalid("CA file contains no certificates")
		}
	}
	// Request contexts own deadlines, so a per-request override can be longer
	// than the session default without an earlier http.Client deadline.
	c := client.NewClient(client.WithPreset(p), client.WithTimeout(0), client.WithInsecureSkipVerify(!o.Verify), client.WithRootCAs(roots))
	if proxy != "" {
		c.SetProxy(proxy)
	}
	if o.Protocol == "h1" {
		c.ForceHTTP1()
	}
	if o.Protocol == "h2" {
		c.UseHTTP2()
	}
	if !o.Redirects {
		c.SetRedirects(0)
	}
	// Configuration setters rebuild http.Client and its jar: enable it last.
	if o.Cookies {
		c.EnableCookieJar()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{client: c, ctx: ctx, cancel: cancel}
	id := nextID.Add(1)
	sessions.Lock()
	sessions.values[id] = s
	sessions.Unlock()
	return map[string]any{"session_id": id, "preset": p.Key}, nil, nil
}

func closeSession(id uint64) {
	sessions.Lock()
	s := sessions.values[id]
	delete(sessions.values, id)
	sessions.Unlock()
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.active.Wait()
	s.client.Close()
}

func execute(id uint64, r request, body []byte) (any, []byte, error) {
	sessions.Lock()
	s := sessions.values[id]
	sessions.Unlock()
	if s == nil {
		return nil, nil, &apiError{"SessionClosed", "session is closed"}
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, nil, &apiError{"SessionClosed", "session is closed"}
	}
	s.active.Add(1)
	s.mu.Unlock()
	defer s.active.Done()
	u, err := url.Parse(r.URL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, nil, invalid("URL must use http:// or https:// and include a host")
	}
	if math.IsNaN(r.Timeout) || math.IsInf(r.Timeout, 0) || r.Timeout < 0 || r.Timeout >= float64(math.MaxInt64)/1e9 {
		return nil, nil, invalid("timeout must be a finite non-negative number of seconds")
	}
	ctx := s.ctx
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(r.Timeout*1e9))
		defer cancel()
	}
	req := s.client.R().SetContext(ctx).SetHeaders(r.Headers)
	if r.HasBody {
		req.SetBody(body)
	}
	start := time.Now()
	resp, err := req.Execute(r.Method, r.URL)
	if err != nil {
		return nil, nil, err
	}
	return map[string]any{
		"status_code": resp.StatusCode(), "status": resp.Status(), "headers": resp.Header(),
		"url": resp.RequestURL(), "http_version": resp.Proto(), "elapsed": time.Since(start).Seconds(),
	}, resp.Body(), nil
}

func dispatch(c command, body []byte) (any, []byte, error) {
	switch c.Op {
	case "new_session":
		return createSession(c.Options)
	case "close_session":
		closeSession(c.SessionID)
		return map[string]bool{"closed": true}, nil, nil
	case "request":
		return execute(c.SessionID, c.Request, body)
	case "list_presets", "get_preset":
		reg, err := preset.Builtin()
		if err != nil {
			return nil, nil, err
		}
		if c.Op == "get_preset" {
			p := reg.Lookup(c.Name)
			if p == nil {
				return nil, nil, invalid("unknown preset: " + c.Name)
			}
			return p, nil, nil
		}
		out := make([]*preset.Preset, 0)
		for _, p := range reg.List() {
			if c.Product == "" || strings.EqualFold(p.Product, c.Product) {
				out = append(out, p)
			}
		}
		return out, nil, nil
	default:
		return nil, nil, invalid("unknown operation")
	}
}

func classify(err error) *apiError {
	var api *apiError
	if errors.As(err, &api) {
		return api
	}
	kind := "RequestError"
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certificate x509.CertificateInvalidError
	var neterr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		kind = "Timeout"
	case errors.Is(err, context.Canceled):
		kind = "Cancelled"
	case errors.As(err, &authority), errors.As(err, &hostname), errors.As(err, &certificate):
		kind = "SSLError"
	case errors.As(err, &neterr):
		kind = "ConnectionError"
		if neterr.Timeout() {
			kind = "Timeout"
		}
	}
	return &apiError{kind, err.Error()}
}

func result(meta any, body []byte, err error) *C.tlsprint_result {
	if err != nil {
		meta = map[string]any{"error": classify(err)}
		body = nil
	}
	encoded, marshalErr := json.Marshal(meta)
	if marshalErr != nil {
		encoded = []byte(`{"error":{"type":"RequestError","message":"cannot encode native result"}}`)
		body = nil
	}
	r := (*C.tlsprint_result)(C.malloc(C.size_t(unsafe.Sizeof(C.tlsprint_result{}))))
	r.metadata = C.CBytes(encoded)
	r.metadata_len = C.size_t(len(encoded))
	r.body = nil
	r.body_len = C.size_t(len(body))
	if len(body) > 0 {
		r.body = C.CBytes(body)
	}
	return r
}

//export tlsprint_abi_version
func tlsprint_abi_version() C.uint32_t { return 1 }

//export tlsprint_call
func tlsprint_call(metadata unsafe.Pointer, metadataLen C.size_t, body unsafe.Pointer, bodyLen C.size_t) (out *C.tlsprint_result) {
	defer func() {
		if p := recover(); p != nil {
			out = result(nil, nil, fmt.Errorf("native panic: %v", p))
		}
	}()
	if metadata == nil || metadataLen > 16<<20 || bodyLen > math.MaxInt32 || (bodyLen > 0 && body == nil) {
		return result(nil, nil, invalid("invalid ABI buffer length or pointer"))
	}
	decoder := json.NewDecoder(bytes.NewReader(C.GoBytes(metadata, C.int(metadataLen))))
	decoder.DisallowUnknownFields()
	var c command
	if err := decoder.Decode(&c); err != nil {
		return result(nil, nil, invalid("invalid command: "+err.Error()))
	}
	meta, payload, err := dispatch(c, C.GoBytes(body, C.int(bodyLen)))
	return result(meta, payload, err)
}

//export tlsprint_free
func tlsprint_free(r *C.tlsprint_result) {
	if r != nil {
		C.free(r.metadata)
		C.free(r.body)
		C.free(unsafe.Pointer(r))
	}
}

func main() {}
