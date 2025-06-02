# Stage 1: Build
FROM golang:1.24-alpine AS builder

# Install git
RUN apk add --no-cache git

# Configure git to use token
ARG GITHUB_TOKEN
RUN git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"

# Set up Go private module
ENV GOPRIVATE=github.com/getaxal/*

WORKDIR /app

# Copy everything (both modules)
COPY . .

# Build from the enclave directory
WORKDIR /app/enclave
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -v -a -installsuffix cgo -o main ./cmd

# Stage 2: Runtime image
FROM alpine:latest
WORKDIR /root/

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/enclave/main .
RUN chmod +x ./main

COPY enclave/config.yaml ./config.yaml
CMD ["./main"]