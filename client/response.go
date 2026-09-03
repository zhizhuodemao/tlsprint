package client

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Response wraps an HTTP response with the body already read into memory.
//
// The body is transparently decoded based on the response Content-Encoding
// header (gzip, deflate, br, zstd), so String()/Body()/JSON() operate on the
// readable content. RawBody() returns the original wire bytes.
type Response struct {
	statusCode int
	status     string
	header     http.Header
	proto      string
	rawBody    []byte // bytes as received on the wire (possibly compressed)
	body       []byte // decoded content (see decodeBody)
	requestURL string
	duration   time.Duration
}

// StatusCode returns the HTTP status code.
func (r *Response) StatusCode() int { return r.statusCode }

// Status returns the full status line, e.g. "200 OK".
func (r *Response) Status() string { return r.status }

// Header returns the response headers.
func (r *Response) Header() http.Header { return r.header }

// Body returns the decoded response body bytes (gzip/deflate/br/zstd are
// decompressed automatically based on Content-Encoding). Use RawBody for the
// undecoded wire bytes.
func (r *Response) Body() []byte { return r.body }

// RawBody returns the response body exactly as received on the wire — still
// compressed when the server used a content encoding.
func (r *Response) RawBody() []byte { return r.rawBody }

// String returns the decoded response body as a string.
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

// JSON decodes the (decompressed) response body into v.
func (r *Response) JSON(v any) error { return json.Unmarshal(r.body, v) }

// decodeBody decompresses a response body according to its Content-Encoding
// header. Encodings are applied in order, so they are decoded in reverse. Any
// unknown encoding or decode failure falls back to the raw bytes so no data is
// lost.
func decodeBody(contentEncoding string, raw []byte) []byte {
	if contentEncoding == "" || strings.EqualFold(contentEncoding, "identity") {
		return raw
	}
	tokens := strings.Split(contentEncoding, ",")
	out := raw
	// Content-Encoding lists encodings in the order applied; decode in reverse.
	for i := len(tokens) - 1; i >= 0; i-- {
		enc := strings.ToLower(strings.TrimSpace(tokens[i]))
		var reader io.Reader
		switch enc {
		case "gzip":
			gz, err := gzip.NewReader(bytes.NewReader(out))
			if err != nil {
				return raw
			}
			reader = gz
		case "deflate":
			zr, err := zlib.NewReader(bytes.NewReader(out))
			if err != nil {
				return raw
			}
			reader = zr
		case "br":
			reader = brotli.NewReader(bytes.NewReader(out))
		case "zstd":
			zd, err := zstd.NewReader(bytes.NewReader(out))
			if err != nil {
				return raw
			}
			defer zd.Close()
			reader = zd
		default:
			// Unknown content encoding: don't guess, return the raw bytes.
			return raw
		}
		decoded, err := io.ReadAll(reader)
		if err != nil {
			return raw
		}
		out = decoded
	}
	return out
}
