# Build stage. --platform=$BUILDPLATFORM keeps the compiler running natively
# and cross-compiles to the requested target, which is much faster than
# emulating the build under QEMU for each architecture.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.6@sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6 AS builder

WORKDIR /workspace

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

# Copy sources.
COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/

# Build a static binary for the requested target platform. TARGETOS/TARGETARCH
# are provided automatically by Buildx.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -a -ldflags="-s -w" -o manager ./cmd

# Runtime stage: distroless nonroot.
FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
WORKDIR /
COPY --from=builder /workspace/manager /manager
USER 65532:65532

ENTRYPOINT ["/manager"]
