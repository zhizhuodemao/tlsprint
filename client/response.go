package client

import (
	"encoding/json"
	"net/http"
	"time"
)

// Response wraps an HTTP response with the body already read into memory.
type Response struct {
	statusCode int
	status     string
	header     http.Header
	proto      string
	body       []byte
	requestURL string
	duration   time.Duration
}

// StatusCode returns the HTTP status code.
func (r *Response) StatusCode() int { return r.statusCode }

// Status returns the full status line, e.g. "200 OK".
func (r *Response) Status() string { return r.status }

// Header returns the response headers.
func (r *Response) Header() http.Header { return r.header }

// Body returns the response body bytes.
func (r *Response) Body() []byte { return r.body }

// String returns the response body as a string.
func (r *Response) String() string { return string(r.body) }

// Proto returns the response protocol, e.g. "HTTP/2.0".
func (r *Response) Proto() string { return r.proto }

// Cookies parses the Set-Cookie response headers.
func (r *Response) Cookies() []*http.Cookie {
	var out []*http.Cookie
	for _, v := range r.header.Values("Set-Cookie") {
		if c, err := http.ParseSetCookie(v); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// Time returns the request duration.
func (r *Response) Time() time.Duration { return r.duration }

// RequestURL returns the final request URL (after redirects and params).
func (r *Response) RequestURL() string { return r.requestURL }

// IsSuccess reports whether the status is 2xx.
func (r *Response) IsSuccess() bool {
	return r.statusCode >= 200 && r.statusCode < 300
}

// IsError reports whether the status is 4xx or 5xx.
func (r *Response) IsError() bool {
	return r.statusCode >= 400 && r.statusCode < 600
}

// JSON decodes the response body into v.
func (r *Response) JSON(v any) error { return json.Unmarshal(r.body, v) }
