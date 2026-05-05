# Reduit — multi-stage Docker build.
#
# Build stage compiles the reduit binary statically; runtime stage
# ships only the binary, embedded migrations, and CA certificates.
# Image is roughly 25–35 MiB depending on Go version.

ARG GO_VERSION=1.26

# ---- build -----------------------------------------------------------------
FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# Install build tools for static cgo-free build.
RUN apk add --no-cache git ca-certificates

# Cache go mod downloads.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build.
COPY . .

ARG VERSION=docker
RUN CGO_ENABLED=0 \
    go build \
        -trimpath \
        -ldflags "-s -w -X github.com/joestump/reduit/internal/cli.Version=${VERSION}" \
        -o /out/reduit \
        ./cmd/reduit

# ---- runtime ---------------------------------------------------------------
FROM alpine:3.20

# Non-root user. UID/GID 10000 to avoid colliding with host UIDs that
# self-hosters often use.
RUN addgroup -S -g 10000 reduit \
 && adduser  -S -u 10000 -G reduit reduit \
 && apk add --no-cache ca-certificates tzdata \
 && mkdir -p /var/lib/reduit /etc/reduit/tls \
 && chown -R reduit:reduit /var/lib/reduit \
 && chmod 0700 /var/lib/reduit

COPY --from=build /out/reduit /usr/local/bin/reduit

# Standard volume mounts:
#   /var/lib/reduit  — persistent data (sqlite + master.key)
#   /etc/reduit      — config + cert/key files
VOLUME ["/var/lib/reduit", "/etc/reduit"]

# HTTPS / IMAPS / SMTPS listeners.
EXPOSE 443 993 465

USER reduit
ENTRYPOINT ["/usr/local/bin/reduit"]
CMD ["serve"]
