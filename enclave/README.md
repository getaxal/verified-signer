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
- **GET** `/api/v1/user` - Retrieve the authenticated Privy user
- **POST** `/api/v1/user/wallet` - Provision an additional delegated EVM wallet for the authenticated user

#### Wallet provisioning

A user may hold several delegated EVM wallets — one per pot of money, so balances
and PnL can be tracked apart. `POST /api/v1/user/wallet` provisions one and returns
it as a linked account:

```jsonc
// request                          // response: 200, the wallet
{ "purpose": "wealth_plan" }        { "id": "...", "type": "wallet", "address": "0x...",
                                      "chain_type": "ethereum", "wallet_index": 1,
                                      "delegated": true, "external_id": "<subject>-wealth_plan" }
```

Wallets are named by **purpose, not HD index**. Privy's server API treats
`wallet_index` as read-only on the wallet it returns — only the client SDK can pin
an index — so an index in the request would name something the enclave cannot
honour. A purpose maps to a stable Privy `external_id` of `<privy DID subject>-<purpose>`,
which is what identifies the wallet on any later call. Purposes are lowercase
`[a-z][a-z0-9_-]{0,31}`; the charset is narrower than it looks because the purpose
becomes part of the external ID, which Privy restricts to `[a-zA-Z0-9_-]`.

**Repeat calls return the existing wallet.** A duplicate wallet is not a failed
request that can be retried away — it is a second address that may already have
received money, with no way to tell which one the user's funds went to. Three
guards stack, so none has to be perfect on its own:

1. a singleflight group keyed on the external ID collapses concurrent callers
   within an enclave into a single create;
2. the create is skipped when the user already holds a wallet with that external ID;
3. Privy receives a deterministic `privy-idempotency-key` and a unique `external_id`,
   which covers retries this process never sees — a caller that gave up and
   redialled, or a second enclave instance.

Only the third guard holds across instances. Privy documents external IDs as unique
per app; that is the property worth verifying rather than assuming.

The wallet is asserted to come back `delegated` on `ethereum` before it is returned,
and the user's cache entry is dropped so the new wallet is resolvable by the very
next signature rather than after the cache TTL.

### Ethereum Signing
- **POST** `/api/v1/user/signer/eth/secp256k1Sign` - User-authenticated raw-hash signature generation
- **POST** `/api/v1/axal/signer/eth/secp256k1Sign` - HMAC-authenticated Axal raw-hash signature generation
- **POST** `/api/v1/axal/signer/eth/personalSign` - HMAC-authenticated EIP-191 personal message signing

#### Wallet selection

A Privy user may hold more than one delegated EVM wallet, so **every signing
route requires the caller to name the wallet to sign with** via a
`wallet_address` field. Send it lowercase and `0x`-prefixed; comparison is
case-insensitive.

The enclave never infers a signer. Before signing, the named address must
resolve to a delegated `ethereum` wallet belonging to the authenticated user —
the user identified by the JWT on the user route, or by `privy_id` on the Axal
routes. An address that is absent, malformed, unknown, or owned by a different
user is rejected. There is no fallback to another wallet: a signature from the
wrong key produces a user operation that fails validation on chain, which is
far more expensive to diagnose than a `4xx`.

The wallet is covered by the request's HMAC on the Axal routes, so it is
authenticated rather than merely asserted. For `secp256k1Sign` the preimage is:

```
hash + ":" + privyId + ":" + walletAddress
```

Anyone able to modify a request body in flight therefore cannot redirect a
signature to another of the user's wallets: changing the address invalidates
the signature, and stripping it leaves an HMAC that does not verify.

The Axal `personalSign` route is provider-neutral. It accepts the `utf-8` and
`hex` encodings supported by Privy, requires a provider-independent purpose,
and verifies the requested wallet as described above. The HMAC covers the
method, purpose, encoding, wallet, SHA-256 message digest, and Privy ID. Raw
messages and signatures are not logged. Callers are responsible for applying
any use-case-specific message or challenge validation before requesting a
signature.

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
