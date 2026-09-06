package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func newTestSession(t *testing.T) uint64 {
	t.Helper()
	meta, _, err := createSession(options{Impersonate: "chrome-142", Verify: true, Protocol: "auto", Redirects: true, Cookies: true})
	if err != nil {
		t.Fatal(err)
	}
	id := meta.(map[string]any)["session_id"].(uint64)
	t.Cleanup(func() { closeSession(id) })
	return id
}

func TestCloseCancelsActiveRequests(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	id := newTestSession(t)
	done := make(chan error, 1)
	go func() {
		_, _, err := execute(id, request{Method: "GET", URL: server.URL, Timeout: 5}, nil)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	closed := make(chan struct{})
	go func() { closeSession(id); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("close blocked")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	_, _, err := execute(id, request{Method: "GET", URL: server.URL}, nil)
	if classify(err).Kind != "SessionClosed" {
		t.Fatalf("expected closed error, got %v", err)
	}
}

func TestConcurrentRequestsAndClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer server.Close()
	for round := 0; round < 5; round++ {
		id := newTestSession(t)
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, err := execute(id, request{Method: "GET", URL: server.URL, Timeout: 5}, nil)
				if err != nil && !errors.Is(err, context.Canceled) && classify(err).Kind != "SessionClosed" {
					t.Errorf("request: %v", err)
				}
			}()
		}
		closeSession(id)
		wg.Wait()
	}
}
