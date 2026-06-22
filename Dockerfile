# syntax=docker/dockerfile:1

# Stage 1: Build the Go enclave binary
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

# Stage 2: Build kmstool_enclave_cli from the AWS Nitro Enclaves SDK.
#
# The enclave shells out to this CLI to perform attestation-bound kms:Decrypt.
# It is a C binary, so it cannot run on distroless/static; the runtime base
# below is changed to amazonlinux:2023 to match this stage's ABI.
#
# IMPORTANT: pin every dependency below to a known-good release and validate the
# resulting binary in CI before shipping. The tags here are a starting point and
# must be reviewed against the SDK release you intend to vendor:
#   https://github.com/aws/aws-nitro-enclaves-sdk-c
FROM amazonlinux:2023 AS kmsbuilder

RUN dnf install -y git cmake gcc gcc-c++ make tar gzip ninja-build perl \
    rust cargo && dnf clean all

ENV PREFIX=/opt/kms
ENV CMAKE_ARGS="-GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    -DCMAKE_INSTALL_PREFIX=${PREFIX} -DCMAKE_PREFIX_PATH=${PREFIX}"
WORKDIR /build

# Dependency chain required by aws-nitro-enclaves-sdk-c, built in order.
RUN git clone --depth 1 -b v1.39.0 https://github.com/aws/aws-lc.git && \
    cmake -S aws-lc -B aws-lc/build ${CMAKE_ARGS} && \
    cmake --build aws-lc/build --target install
RUN git clone --depth 1 -b v1.5.10 https://github.com/aws/s2n-tls.git && \
    cmake -S s2n-tls -B s2n-tls/build ${CMAKE_ARGS} && \
    cmake --build s2n-tls/build --target install
RUN git clone --depth 1 -b v0.12.3 https://github.com/awslabs/aws-c-common.git && \
    cmake -S aws-c-common -B aws-c-common/build ${CMAKE_ARGS} && \
    cmake --build aws-c-common/build --target install
RUN git clone --depth 1 -b v0.2.4 https://github.com/awslabs/aws-c-sdkutils.git && \
    cmake -S aws-c-sdkutils -B aws-c-sdkutils/build ${CMAKE_ARGS} && \
    cmake --build aws-c-sdkutils/build --target install
RUN git clone --depth 1 -b v0.8.9 https://github.com/awslabs/aws-c-cal.git && \
    cmake -S aws-c-cal -B aws-c-cal/build ${CMAKE_ARGS} && \
    cmake --build aws-c-cal/build --target install
RUN git clone --depth 1 -b v0.21.4 https://github.com/awslabs/aws-c-io.git && \
    cmake -S aws-c-io -B aws-c-io/build ${CMAKE_ARGS} -DUSE_VSOCK=1 && \
    cmake --build aws-c-io/build --target install
RUN git clone --depth 1 -b v0.3.1 https://github.com/awslabs/aws-c-compression.git && \
    cmake -S aws-c-compression -B aws-c-compression/build ${CMAKE_ARGS} && \
    cmake --build aws-c-compression/build --target install
RUN git clone --depth 1 -b v0.10.4 https://github.com/awslabs/aws-c-http.git && \
    cmake -S aws-c-http -B aws-c-http/build ${CMAKE_ARGS} && \
    cmake --build aws-c-http/build --target install
RUN git clone --depth 1 -b v0.9.0 https://github.com/awslabs/aws-c-auth.git && \
    cmake -S aws-c-auth -B aws-c-auth/build ${CMAKE_ARGS} && \
    cmake --build aws-c-auth/build --target install
RUN git clone --depth 1 -b json-c-0.18-20240915 https://github.com/json-c/json-c.git && \
    cmake -S json-c -B json-c/build ${CMAKE_ARGS} && \
    cmake --build json-c/build --target install

# NSM API (Rust) provides libnsm, linked by kmstool_enclave_cli.
RUN git clone --depth 1 -b v0.4.0 https://github.com/aws/aws-nitro-enclaves-nsm-api.git && \
    cd aws-nitro-enclaves-nsm-api && \
    cargo build --release -p nsm-lib && \
    cp target/release/libnsm.so ${PREFIX}/lib/ && \
    cp target/release/nsm.h ${PREFIX}/include/ 2>/dev/null || true

# The SDK itself, which produces kmstool_enclave_cli.
RUN git clone --depth 1 -b v0.4.1 https://github.com/aws/aws-nitro-enclaves-sdk-c.git && \
    cmake -S aws-nitro-enclaves-sdk-c -B aws-nitro-enclaves-sdk-c/build ${CMAKE_ARGS} && \
    cmake --build aws-nitro-enclaves-sdk-c/build --target install && \
    install -m 0755 aws-nitro-enclaves-sdk-c/build/bin/kmstool-enclave-cli/kmstool_enclave_cli ${PREFIX}/bin/kmstool_enclave_cli

# Stage 3: Runtime (amazonlinux:2023 so the C CLI can run)
FROM amazonlinux:2023

# CA certificates for TLS to KMS/Secrets Manager
RUN dnf install -y ca-certificates && dnf clean all

# Go enclave binary (static)
COPY --from=builder /app/enclave/main /main

# Config file
COPY --from=builder /app/enclave/config.yaml /config.yaml

# kmstool CLI plus the shared libs it links against
COPY --from=kmsbuilder /opt/kms/bin/kmstool_enclave_cli /kmstool_enclave_cli
COPY --from=kmsbuilder /opt/kms/lib/ /opt/kms/lib/
ENV LD_LIBRARY_PATH=/opt/kms/lib

CMD ["/main", "-config", "/config.yaml"]
