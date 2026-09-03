package client

import "net/http"

// Top-level convenience functions mirror curl_cffi's module-level
// requests.get/post: call them directly and pass the fingerprint via
// Impersonate, plus any request options.
//
//	resp, err := client.Get("https://tls.peet.ws/api/all",
//	    client.Impersonate("chrome-152"))
//
//	resp, err = client.Post("https://httpbin.org/post",
//	    client.Impersonate("firefox-145"),
//	    client.Body(map[string]any{"name": "tlsprint"}),
//	    client.Header("X-Api-Key", "secret"))
//
// Each call uses a short-lived client (a new connection pool), matching the
// ergonomics of module-level curl_cffi helpers. Use client.NewClient +
// Client.R() when you want a reusable session with keep-alive.
func Get(rawURL string, opts ...any) (*Response, error) {
	return call(http.MethodGet, rawURL, opts...)
}

// Post is the module-level POST convenience.
func Post(rawURL string, opts ...any) (*Response, error) {
	return call(http.MethodPost, rawURL, opts...)
}

// Put is the module-level PUT convenience.
func Put(rawURL string, opts ...any) (*Response, error) {
	return call(http.MethodPut, rawURL, opts...)
}

// Patch is the module-level PATCH convenience.
func Patch(rawURL string, opts ...any) (*Response, error) {
	return call(http.MethodPatch, rawURL, opts...)
}

// Delete is the module-level DELETE convenience.
func Delete(rawURL string, opts ...any) (*Response, error) {
	return call(http.MethodDelete, rawURL, opts...)
}

// Head is the module-level HEAD convenience.
func Head(rawURL string, opts ...any) (*Response, error) {
	return call(http.MethodHead, rawURL, opts...)
}

// Options is the module-level OPTIONS convenience.
func Options(rawURL string, opts ...any) (*Response, error) {
	return call(http.MethodOptions, rawURL, opts...)
}

// Do is the module-level generic verb convenience.
func Do(method, rawURL string, opts ...any) (*Response, error) {
	return call(method, rawURL, opts...)
}

// call applies a mix of Client options (e.g. Impersonate) and request options
// to a fresh client and executes one request.
func call(method, rawURL string, opts ...any) (*Response, error) {
	c := NewClient()
	defer c.CloseIdleConnections()
	var reqs []ReqOption
	for _, o := range opts {
		switch v := o.(type) {
		case Option:
			v(c)
		case ReqOption:
			reqs = append(reqs, v)
		}
	}
	r := c.R()
	for _, ro := range reqs {
		ro(r)
	}
	return r.Execute(method, rawURL)
}

// ---- Client-level direct verbs (reuse the client's connection pool) ----

// Get performs a GET on the client's pool. reqs are request options.
func (c *Client) Get(rawURL string, reqs ...ReqOption) (*Response, error) {
	return c.doVerb(http.MethodGet, rawURL, reqs...)
}

// Post performs a POST on the client's pool.
func (c *Client) Post(rawURL string, reqs ...ReqOption) (*Response, error) {
	return c.doVerb(http.MethodPost, rawURL, reqs...)
}

// Put performs a PUT on the client's pool.
func (c *Client) Put(rawURL string, reqs ...ReqOption) (*Response, error) {
	return c.doVerb(http.MethodPut, rawURL, reqs...)
}

// Patch performs a PATCH on the client's pool.
func (c *Client) Patch(rawURL string, reqs ...ReqOption) (*Response, error) {
	return c.doVerb(http.MethodPatch, rawURL, reqs...)
}

// Delete performs a DELETE on the client's pool.
func (c *Client) Delete(rawURL string, reqs ...ReqOption) (*Response, error) {
	return c.doVerb(http.MethodDelete, rawURL, reqs...)
}

// Head performs a HEAD on the client's pool.
func (c *Client) Head(rawURL string, reqs ...ReqOption) (*Response, error) {
	return c.doVerb(http.MethodHead, rawURL, reqs...)
}

// Options performs an OPTIONS on the client's pool.
func (c *Client) Options(rawURL string, reqs ...ReqOption) (*Response, error) {
	return c.doVerb(http.MethodOptions, rawURL, reqs...)
}

// Do performs a verb on the client's pool.
func (c *Client) Do(method, rawURL string, reqs ...ReqOption) (*Response, error) {
	return c.doVerb(method, rawURL, reqs...)
}

func (c *Client) doVerb(method, rawURL string, reqs ...ReqOption) (*Response, error) {
	r := c.R()
	for _, ro := range reqs {
		ro(r)
	}
	return r.Execute(method, rawURL)
}
