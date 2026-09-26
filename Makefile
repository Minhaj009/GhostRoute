.PHONY: all build test demo clean catalog lint

BINARY_NAME=ghostroute

all: test build

build:
	go build -ldflags "-s -w" -o $(BINARY_NAME) ./cmd/ghostroute

test:
	go test -v -cover ./...

test-race:
	go test -v -race -cover ./...

demo:
	go run ./cmd/ghostroute scan --demo

catalog:
	go run ./cmd/ghostroute catalog

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe *.sarif *.sh
