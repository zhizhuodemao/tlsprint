package http2_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	http2 "github.com/lingulingo/tlsprint/http2"
	hpack "github.com/lingulingo/tlsprint/http2/hpack"
)

// capturedFrames is what the local h2 server observed from the client.
type capturedFrames struct {
	settings       []http2.Setting
	windowUpd      uint32
	priority       *http2.StreamPriority
	headerPriority *http2.StreamPriority
	pseudo         []string
	headers        []string
}

// newCaptureServer runs a raw HTTP/2 server (h2c) on 127.0.0.1:0 that reads
// the client preface and frames, recording the connection fingerprint, then
// stops. It returns the listener address and the capture channel.
func newCaptureServer(t *testing.T) (string, chan capturedFrames) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	ch := make(chan capturedFrames, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		// Client preface.
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(br, preface); err != nil {
			ch <- capturedFrames{}
			return
		}
		if string(preface) != http2.ClientPreface {
			ch <- capturedFrames{}
			return
		}

		fr := http2.NewFramer(conn, br)
		dec := hpack.NewDecoder(4096, nil)
		var cap capturedFrames
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				break
			}
			switch ff := f.(type) {
			case *http2.SettingsFrame:
				ff.ForeachSetting(func(s http2.Setting) error {
					cap.settings = append(cap.settings, s)
					return nil
				})
			case *http2.WindowUpdateFrame:
				cap.windowUpd = ff.Increment
			case *http2.PriorityFrame:
				cap.priority = &http2.StreamPriority{
					StreamDep: ff.StreamDep,
					Exclusive: ff.Exclusive,
					Weight:    ff.Weight,
				}
			case *http2.HeadersFrame:
				cap.headerPriority = &http2.StreamPriority{
					StreamDep: ff.Priority.StreamDep,
					Exclusive: ff.Priority.Exclusive,
					Weight:    ff.Priority.Weight,
				}
				var fields []hpack.HeaderField
				dec.SetEmitFunc(func(f hpack.HeaderField) { fields = append(fields, f) })
				if _, err := dec.Write(ff.HeaderBlockFragment()); err != nil {
					break
				}
				for _, f := range fields {
					if strings.HasPrefix(f.Name, ":") {
						cap.pseudo = append(cap.pseudo, f.Name)
					} else {
						cap.headers = append(cap.headers, f.Name)
					}
				}
				ch <- cap
				return
			}
		}
		ch <- cap
	}()
	return ln.Addr().String(), ch
}

func TestTransportFingerprint(t *testing.T) {
	addr, ch := newCaptureServer(t)

	order := []string{"sec-ch-ua", "sec-ch-ua-mobile", "user-agent", "accept", "priority"}
	tr := &http2.Transport{
		AllowHTTP:          true,
		DisableCompression: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		Fingerprint: &http2.Fingerprint{
			Settings: []http2.Setting{
				{ID: http2.SettingHeaderTableSize, Val: 65536},
				{ID: http2.SettingEnablePush, Val: 0},
				{ID: http2.SettingInitialWindowSize, Val: 6291456},
				{ID: http2.SettingMaxHeaderListSize, Val: 262144},
			},
			WindowUpdate:      15663105,
			PseudoHeaderOrder: []string{"m", "a", "s", "p"},
			HeaderOrder:       order,
			HeaderPriority:    &http2.StreamPriority{StreamDep: 0, Exclusive: true, Weight: 255},
			PriorityFrames: []http2.StreamPriorityFrame{
				{StreamID: 3, Priority: http2.StreamPriority{StreamDep: 0, Exclusive: true, Weight: 254}},
			},
		},
	}
	defer tr.CloseIdleConnections()

	req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="152"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/152")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("X-Extra", "zzz") // not in HeaderOrder -> must be appended

	// Fire the request in the background; the capture server reads frames.
	go func() {
		resp, err := tr.RoundTrip(req)
		if resp != nil {
			resp.Body.Close()
		}
		_ = err
	}()

	select {
	case cap := <-ch:
		checkCaptured(t, cap, order)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for captured frames")
	}
}

func checkCaptured(t *testing.T, cap capturedFrames, order []string) {
	t.Helper()
	wantSettings := []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 6291456},
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	}
	if len(cap.settings) != len(wantSettings) {
		t.Fatalf("settings = %+v, want %d entries", cap.settings, len(wantSettings))
	}
	for i, w := range wantSettings {
		if cap.settings[i] != w {
			t.Fatalf("settings[%d] = %+v, want %+v", i, cap.settings[i], w)
		}
	}
	if cap.windowUpd != 15663105 {
		t.Fatalf("window update = %d, want 15663105", cap.windowUpd)
	}
	wantPseudo := []string{":method", ":authority", ":scheme", ":path"}
	if strings.Join(cap.pseudo, ",") != strings.Join(wantPseudo, ",") {
		t.Fatalf("pseudo order = %v, want %v", cap.pseudo, wantPseudo)
	}
	// Headers must start with the configured order (present ones), then extras.
	if len(cap.headers) < len(order) {
		t.Fatalf("headers = %v, want order %v", cap.headers, order)
	}
	for i, name := range order {
		if cap.headers[i] != name {
			t.Fatalf("header[%d] = %q, want %q (order %v)", i, cap.headers[i], name, cap.headers)
		}
	}
	// X-Extra (not in order) must appear after the ordered block.
	found := false
	for _, h := range cap.headers[len(order):] {
		if h == "x-extra" {
			found = true
		}
	}
	if !found {
		t.Fatalf("x-extra missing from trailing headers: %v", cap.headers)
	}
	// Priority attached to the HEADERS frame.
	if cap.headerPriority == nil || cap.headerPriority.Exclusive != true || cap.headerPriority.Weight != 255 || cap.headerPriority.StreamDep != 0 {
		t.Fatalf("header priority = %+v, want {0 true 255}", cap.headerPriority)
	}
	// Explicit PRIORITY frame from Fingerprint.PriorityFrames.
	if cap.priority == nil || cap.priority.Weight != 254 || cap.priority.Exclusive != true {
		t.Fatalf("priority frame = %+v, want weight 254 exclusive", cap.priority)
	}
}
