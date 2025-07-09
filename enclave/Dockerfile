# syntax=docker/dockerfile:1

# Stage 1: Build
FROM golang:1.24-alpine AS builder

# Install necessary packages
RUN apk add --no-cache git openssh-client

# Set up Go private module
ENV GOPRIVATE=github.com/getaxal/*
ENV GOPROXY=direct
ENV GOSUMDB=off

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies with SSH mount
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -a -installsuffix cgo -o main ./cmd

# Stage 2: Runtime image
FROM alpine:latest

WORKDIR /root/

# Install CA certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

# Copy the binary from builder stage
COPY --from=builder /app/main .
RUN chmod +x ./main

# Copy config file
COPY config.yaml /root/config.yaml

# Run the application
CMD ["/root/main", "-config", "/root/config.yaml"]