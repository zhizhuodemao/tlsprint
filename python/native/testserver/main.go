// A loopback-only integration fixture, not part of the runtime API.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/lingulingo/tlsprint/hello"
	"github.com/lingulingo/tlsprint/http2"
	"github.com/lingulingo/tlsprint/http2/hpack"
	"github.com/lingulingo/tlsprint/ja3"
)

var proxyCount atomic.Int64

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/slow":
		ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
		select {
		case <-time.After(time.Duration(ms) * time.Millisecond):
		case <-r.Context().Done():
			return
		}
	case "/redirect":
		to := r.URL.Query().Get("to")
		if to == "" {
			to = "/echo"
		}
		http.Redirect(w, r, to, http.StatusFound)
		return
	case "/cookies":
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "fixture", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "second", Value: "two", Path: "/"})
	case "/gzip":
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte(`{"message":"compressed"}`))
		gz.Close()
		return
	case "/binary":
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte{0, 255, 128, 0, 65})
		return
	case "/status":
		w.WriteHeader(418)
	case "/proxy-count":
		json.NewEncoder(w).Encode(proxyCount.Load())
		return
	}
	body, _ := io.ReadAll(r.Body)
	json.NewEncoder(w).Encode(map[string]any{
		"method": r.Method, "body": base64.StdEncoding.EncodeToString(body),
		"headers": r.Header, "query": r.URL.Query(), "remote": r.RemoteAddr,
	})
}

func proxy(w http.ResponseWriter, r *http.Request) {
	proxyCount.Add(1)
	if r.Method == "CONNECT" {
		upstream, err := net.DialTimeout("tcp", r.Host, 3*time.Second)
		if err != nil {
			http.Error(w, "fixture dial failed", 502)
			return
		}
		defer upstream.Close()
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { io.Copy(upstream, buffered); upstream.Close() }()
		io.Copy(conn, upstream)
		return
	}
	r.RequestURI = ""
	r.Header.Del("Proxy-Authorization")
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, "fixture forwarding failed", 502)
		return
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func capture(raw net.Conn, config *tls.Config) {
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	header := make([]byte, 5)
	if _, err := io.ReadFull(raw, header); err != nil {
		return
	}
	record := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
	if _, err := io.ReadFull(raw, record); err != nil {
		return
	}
	record = append(header, record...)
	ch, err := hello.Parse(record)
	if err != nil {
		return
	}
	conn := tls.Server(&replayConn{raw, io.MultiReader(bytes.NewReader(record), raw)}, config)
	if err := conn.Handshake(); err != nil {
		return
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		return
	}
	settings := make([]map[string]uint32, 0)
	var window uint32
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				f.ForeachSetting(func(s http2.Setting) error {
					settings = append(settings, map[string]uint32{"id": uint32(s.ID), "value": s.Val})
					return nil
				})
				fr.WriteSettingsAck()
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				window = f.Increment
			}
		case *http2.MetaHeadersFrame:
			pseudo := make([]string, 0)
			names := make([]string, 0)
			for _, field := range f.Fields {
				if field.IsPseudo() {
					pseudo = append(pseudo, field.Name)
				} else {
					names = append(names, field.Name)
				}
			}
			body, _ := json.Marshal(map[string]any{"ja3": ja3.Compute(ch), "settings": settings, "window": window, "pseudo": pseudo, "headers": names})
			var block bytes.Buffer
			encoder := hpack.NewEncoder(&block)
			encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			encoder.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})
			fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: block.Bytes(), EndHeaders: true})
			fr.WriteData(f.StreamID, true, body)
			// Let the client consume END_STREAM and close its session. Closing
			// with unread SETTINGS ACK/WINDOW_UPDATE bytes can send a TCP reset
			// on Windows before the response body has reached the client.
			io.Copy(io.Discard, conn)
			return
		}
	}
}

func main() {
	h := http.HandlerFunc(handler)
	plain := httptest.NewServer(h)
	defer plain.Close()
	h1 := httptest.NewUnstartedServer(h)
	h1.Config.ErrorLog = log.New(io.Discard, "", 0)
	h1.StartTLS()
	defer h1.Close()
	h2 := httptest.NewUnstartedServer(h)
	h2.EnableHTTP2 = true
	h2.Config.ErrorLog = log.New(io.Discard, "", 0)
	h2.StartTLS()
	defer h2.Close()
	pr := httptest.NewServer(http.HandlerFunc(proxy))
	defer pr.Close()
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
	}))
	defer stall.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	cfg := &tls.Config{Certificates: h2.TLS.Certificates, NextProtos: []string{"h2"}}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go capture(conn, cfg)
		}
	}()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h2.TLS.Certificates[0].Certificate[0]})
	json.NewEncoder(os.Stdout).Encode(map[string]string{
		"http": plain.URL, "h1": h1.URL, "h2": h2.URL, "proxy": pr.URL,
		"stall_proxy": stall.URL, "capture": "https://localhost:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), "ca": string(cert),
	})
	bufio.NewReader(os.Stdin).ReadString('\n')
}
