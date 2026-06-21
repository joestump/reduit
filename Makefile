# Reduit Makefile
#
# Common targets:
#   make build      compile the reduit binary into ./bin/reduit
#   make test       go test -race ./...
#   make fmt        gofmt + goimports
#   make lint       go vet + staticcheck (if installed)
#   make tidy       go mod tidy
#   make run        go run ./cmd/reduit serve (with REDUIT_CONFIG=./reduit.yaml)
#   make docker     build the deployment Docker image

GO         ?= go
PKG         := github.com/joestump/reduit
BIN_DIR     := bin
BINARY      := $(BIN_DIR)/reduit
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
LDFLAGS     := -X $(PKG)/internal/cli.Version=$(VERSION)
DOCKER_IMG  ?= ghcr.io/joestump/reduit
DOCKER_TAG  ?= $(VERSION)

.PHONY: all
all: fmt lint test build

.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/reduit

# css rebuilds the committed Tailwind 4 + DaisyUI 5 bundle from
# web/app.css into internal/server/static/vendor/app.css. The Go build
# embeds that committed file (go:embed), so this runs only when
# templates or the theme change -- NOT at `go build`, in CI, or in the
# Dockerfile. Requires Node (npx) to fetch the pinned Tailwind CLI +
# DaisyUI; nothing else in the toolchain does. Re-commit the output.
#
# Governing: ADR-0005 (pre-built committed CSS, no runtime CDN/bundler).
CSS_SRC := web/app.css
CSS_OUT := internal/server/static/vendor/app.css
.PHONY: css
css:
	cd web && npm install --no-audit --no-fund \
	  @tailwindcss/cli@4.2.4 tailwindcss@4.2.4 daisyui@5.0.0
	cd web && ./node_modules/.bin/tailwindcss -i ./app.css \
	  -o ../$(CSS_OUT) --minify
	@echo "Rebuilt $(CSS_OUT) -- commit it."

.PHONY: test
test:
	$(GO) test -race -count=1 ./...

.PHONY: cover
cover:
	$(GO) test -race -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: fmt
fmt:
	$(GO) fmt ./...
	@command -v goimports >/dev/null 2>&1 && goimports -w . || true

.PHONY: lint
lint:
	$(GO) vet ./...
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed; skipping"

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: run
run: build
	REDUIT_CONFIG=./reduit.yaml ./$(BINARY) serve

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) coverage.out

.PHONY: docker
docker:
	docker build -t $(DOCKER_IMG):$(DOCKER_TAG) -f deploy/docker/Dockerfile .

.PHONY: help
help:
	@grep -E '^\.PHONY|^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | grep -v '\.PHONY' || true
