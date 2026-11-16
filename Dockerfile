# Build stage. --platform=$BUILDPLATFORM keeps the compiler running natively
# and cross-compiles to the requested target, which is much faster than
# emulating the build under QEMU for each architecture.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS builder

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
FROM gcr.io/distroless/static:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
WORKDIR /
COPY --from=builder /workspace/manager /manager
USER 65532:65532

ENTRYPOINT ["/manager"]
