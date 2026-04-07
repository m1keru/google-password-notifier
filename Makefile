BINARY_NAME := google-password-notifier
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test lint clean docker-build

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/notifier/

test:
	go test -v -race ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/

docker-build:
	docker build -t $(BINARY_NAME):$(VERSION) .
