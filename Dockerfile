# syntax=docker/dockerfile:1

# Stage 1: Build
FROM golang:1.24-alpine AS builder

# Install necessary packages
RUN apk add --no-cache git openssh-client

# Set up Go private module
ENV GOPROXY=direct
ENV GOSUMDB=off

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

# Build the application
WORKDIR /app/enclave
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -a -installsuffix cgo -o main ./cmd

# Stage 2: Runtime image
FROM alpine:latest

WORKDIR /root/

# Install CA certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

# Copy the binary from builder stage
COPY --from=builder /app/enclave/main .

# Copy config file if it exists
COPY --from=builder /app/enclave/config.yaml . 

# Make binary executable
RUN chmod +x ./main

# Run the application
CMD ["/root/main", "-config", "/root/config.yaml"]