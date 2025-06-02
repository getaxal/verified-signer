# Stage 1: Build
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy module files first (important for caching)
COPY enclave/go.mod enclave/go.sum ./

COPY common/ ./common/

# Download dependencies (cached layer if go.mod doesn't change)
RUN go mod download

# Copy the source code
COPY enclave/ ./enclave/

# Build the binary from the main package
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -v -a -installsuffix cgo -o main ./enclave/cmd

# Stage 2: Runtime image
FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/main .

RUN chmod +x ./main

CMD ["./main"]
