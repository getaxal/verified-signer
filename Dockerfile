# syntax=docker/dockerfile:1

# Stage 1: Build
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git openssh-client ca-certificates
ENV GOPROXY=direct

WORKDIR /app

# Copy go mod files from both common and enclave
COPY common/go.mod common/go.sum ./common/
COPY enclave/go.mod enclave/go.sum ./enclave/

# Download dependencies for both modules
WORKDIR /app/common
RUN go mod download

WORKDIR /app/enclave
RUN go mod download

# Copy the source code
WORKDIR /app
COPY common/ ./common/
COPY enclave/ ./enclave/

# Build the application with static linking for Nitro Enclaves
WORKDIR /app/enclave
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -v -a -ldflags '-s -w -extldflags "-static"' \
    -installsuffix cgo \
    -o main ./cmd

# Stage 2: Distroless runtime (includes non-root user)
FROM gcr.io/distroless/static:nonroot

# Copy the static binary
COPY --from=builder /app/enclave/main /main

# Copy config file
COPY --from=builder /app/enclave/config.yaml /config.yaml

# Use single CMD with all arguments
CMD ["/main", "-config", "/config.yaml"]