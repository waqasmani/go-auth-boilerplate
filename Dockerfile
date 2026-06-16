# ─── Build Stage ──────────────────────────────────────────────────────────────
# GO_VERSION is kept in sync with .github/workflows/ci.yml (env.GO_VERSION) so
# the shipped image is built with the same toolchain that runs the test gate.
ARG GO_VERSION=1.25.8
FROM golang:${GO_VERSION}-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build metadata for identifiable, reproducible binaries. Supply via
#   docker build --build-arg VERSION=$(git describe ...) --build-arg COMMIT=... --build-arg BUILD_TIME=...
# Defaults match the placeholders in cmd/api/main.go.
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown

# -trimpath strips local filesystem paths from the binary (reproducibility +
# no path leakage); the -X flags stamp the version vars in package main.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
      -ldflags="-w -s -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}" \
      -o /app/bin/api ./cmd/api

# Create a dedicated unprivileged user entry to copy into the scratch image, so
# the binary can run as a real non-root account (and user.Current() resolves).
RUN echo 'appuser:x:65532:65532:appuser:/:/sbin/nologin' > /etc/passwd.nonroot

# ─── Runtime Stage ────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd.nonroot /etc/passwd
COPY --from=builder /app/bin/api /api

# Run as a non-root, non-privileged user. Running as UID 0 is rejected by
# Kubernetes `restricted` Pod Security Standards (runAsNonRoot) and needlessly
# widens the blast radius of any RCE.
USER 65532:65532

EXPOSE 8080

# Self-probe via the binary's healthcheck subcommand (scratch has no shell/curl).
# /livez is liveness-only so a transient DB/Redis blip never marks the container
# unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/api", "healthcheck"]

ENTRYPOINT ["/api"]
