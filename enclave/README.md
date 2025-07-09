# Enclave

The enclave is the core security component of the verified-signer-service, running inside a Trusted Execution Environment (TEE) to ensure transaction integrity and user fund protection. It consists of two main logical components: the **Privy Signer** and the **Transaction Verifier**.

## Architecture Overview

The enclave operates as a secure intermediary that:
1. **Verifies** transactions against user-defined rules and safety constraints
2. **Signs** approved transactions through Privy's delegated signing infrastructure
3. **Attests** to its integrity and authenticity through TEE capabilities

All external communication is secured through HTTPS connections that cannot be intercepted by the host system due to TLS encryption.

## Components

### 1. Privy Signer
The Privy Signer handles the actual signing of transactions after they have been verified. It:
- Sends transaction signature requests to Privy's backend via secure HTTPS
- Manages session keys for delegated signing
- Ensures signed transactions match verified parameters

### 2. Transaction Verifier
The Transaction Verifier implements safety checks and validates transactions against user-defined rules:
- Verifies transaction traits to ensure user interests are protected
- Implements safeguards to guard user funds
- Retrieves up-to-date blockchain information through RPC feeds (HTTPS)
- Validates transaction parameters against strategy constraints

## API Endpoints

### Health Check
- **GET** `/api/v1/health/ping` - Health check endpoint for service availability

### User Management
- **GET** `/api/v1/user/:userId` - Retrieve user information and configuration

### Ethereum Signing
- **POST** `/api/v1/signer/eth/ethSignTx/:userId` - Sign Ethereum transactions
- **POST** `/api/v1/signer/eth/ethSendTx/:userId` - Sign and send Ethereum transactions
- **POST** `/api/v1/signer/eth/personalSign/:userId` - Ethereum personal message signing
- **POST** `/api/v1/signer/eth/secp256k1Sign/:userId` - SECP256K1 signature generation

### Solana Signing
- **POST** `/api/v1/signer/sol/solSignTx/:userId` - Sign Solana transactions
- **POST** `/api/v1/signer/sol/solSendTx/:userId` - Sign and send Solana transactions
- **POST** `/api/v1/signer/sol/signMessage/:userId` - Solana message signing

### Attestation
- **GET** `/api/v1/attest/bytes/:nonce` - Get attestation bytes for verification
- **GET** `/api/v1/attest/doc/:nonce` - Get attestation document for integrity proof

## Security Features

### TEE Protection
- All sensitive operations run within the enclave's secure environment
- Host system cannot access or tamper with enclave memory
- Cryptographic attestation proves enclave integrity

### Secure Communication
- All external requests use HTTPS with end-to-end encryption
- Host cannot intercept or modify communication with Privy backend
- RPC connections to blockchain networks are secured via TLS

### Transaction Verification
- Every transaction is verified against user-defined safety rules
- Safeguards prevent malicious or unauthorized transactions
- Real-time blockchain state validation through secure RPC feeds

## Usage

The enclave runs as a service within the TEE and communicates with the host via VSOCK. All API calls are routed through the host, which acts as a proxy to the enclave.

### Request Flow
1. Requester sends request to host
2. Host proxies request to enclave via VSOCK
3. Enclave verifies transaction against user rules
4. If approved, enclave signs transaction via Privy
5. Response is returned through the same path

## Development

### Prerequisites
- TEE-enabled environment (AWS Nitro Enclaves, Intel SGX, etc.)
- Go development environment
- Access to Privy signing infrastructure

### Building
```bash
# Build the docker
./docker-build.sh

# Run on nitro enabled server
./run.sh
```

## Attestation

The enclave provides cryptographic attestation capabilities through the `/api/v1/attest/*` endpoints. These allow external parties to verify:
- The enclave is running genuine, unmodified code
- The enclave is running in a legitimate TEE environment
- The enclave's measurements match expected values

## Security Considerations

- The enclave operates in a zero-trust environment
- All inputs are validated and sanitized
- Cryptographic operations use secure, audited libraries
- Regular security audits and penetration testing
- Open-source enclave code for transparency and verification

