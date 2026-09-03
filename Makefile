GO ?= go

.PHONY: all fmt vet test test-utls build clean

all: fmt vet test

fmt:
	$(GO)fmt -l . || true
	gofmt -w .

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-utls:
	cd utls && $(GO) test ./...

test-client:
	cd client && $(GO) test ./...

test-http2:
	cd http2 && $(GO) test ./...

build:
	$(GO) build ./...

clean:
	rm -f tlsprint
