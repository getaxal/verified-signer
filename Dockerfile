# syntax=docker/dockerfile:1

# Stage 1: Build
FROM golang:1.24-alpine AS builder

# Install necessary packages
RUN apk add --no-cache git openssh-client

# Set up Go private module
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

# Build the application
WORKDIR /app/enclave
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -a -installsuffix cgo -o main ./cmd

# Stage 2: Runtime image
FROM alpine:latest

# Install CA certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

# Create a non-root user and group
RUN addgroup -g 1000 -S appuser && \
    adduser -u 1000 -S appuser -G appuser

# Create app directory and set ownership
RUN mkdir -p /home/appuser/app && \
    chown -R appuser:appuser /home/appuser

# Switch to the app directory
WORKDIR /home/appuser/app

# Copy the binary from builder stage with proper ownership
COPY --from=builder --chown=appuser:appuser /app/enclave/main .

# Copy config file if it exists with proper ownership
COPY --from=builder --chown=appuser:appuser /app/enclave/config.yaml . 

# Make binary executable
RUN chmod +x ./main

# Switch to non-root user
USER appuser

# Run the application
CMD ["./main", "-config", "./config.yaml"]