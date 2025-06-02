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

# Copy enclave directory contents
COPY . .

# Download dependencies and build
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -a -installsuffix cgo -o main ./cmd

# Stage 2: Runtime image
FROM alpine:latest
WORKDIR /root/

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/main .
RUN chmod +x ./main

COPY config.yaml /root/config.yaml
CMD ["/root/main"]