# Build stage. --platform=$BUILDPLATFORM keeps the compiler running natively
# and cross-compiles to the requested target, which is much faster than
# emulating the build under QEMU for each architecture.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder

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
FROM gcr.io/distroless/static:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087
WORKDIR /
COPY --from=builder /workspace/manager /manager
USER 65532:65532

ENTRYPOINT ["/manager"]
