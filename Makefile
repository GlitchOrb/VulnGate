BINARY := vulngate
OUTDIR := bin

.PHONY: fmt lint test build clean build-cross

fmt:
	gofmt -w $(shell find . -type f -name '*.go' -not -path './vendor/*' -not -path './.tools/*')

lint:
	@FILES="$$(find . -type f -name '*.go' -not -path './vendor/*' -not -path './.tools/*')"; \
	if [ -n "$$(gofmt -l $$FILES)" ]; then \
		echo 'gofmt check failed:'; \
		gofmt -l $$FILES; \
		exit 1; \
	fi
	go vet ./...

test:
	go test ./...

build:
	mkdir -p $(OUTDIR)
	go build -o $(OUTDIR)/$(BINARY) ./cmd/vulngate

build-cross:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -o dist/$(BINARY)-linux-amd64 ./cmd/vulngate
	GOOS=linux GOARCH=arm64 go build -o dist/$(BINARY)-linux-arm64 ./cmd/vulngate
	GOOS=darwin GOARCH=amd64 go build -o dist/$(BINARY)-darwin-amd64 ./cmd/vulngate
	GOOS=darwin GOARCH=arm64 go build -o dist/$(BINARY)-darwin-arm64 ./cmd/vulngate
	GOOS=windows GOARCH=amd64 go build -o dist/$(BINARY)-windows-amd64.exe ./cmd/vulngate

clean:
	rm -rf $(OUTDIR) dist coverage.out
