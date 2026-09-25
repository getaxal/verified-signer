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

Full request and response shapes, including the HMAC preimages and error table, are in
[API.md](API.md). The summary below is the route list.

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

The wallet is created on Privy's **wallet API** (`POST /v1/wallets`), with `owner` set
to the user and the enclave's key quorum attached as an `additional_signer`:

```jsonc
{ "chain_type": "ethereum", "external_id": "<subject>-wealth_plan",
  "owner": { "user_id": "did:privy:..." },
  "additional_signers": [ { "signer_id": "<delegated actions key id>" } ] }
```

Not `POST /v1/users/{user_id}/wallets`. That endpoint provisions the embedded wallet a
user does not yet have, and **answers `200` without creating anything** for a chain type
the user already holds — so every request for a second wallet succeeded while minting
nothing. Owner and additional signer are different roles and both are load bearing: the
user owns the wallet, so it is theirs and appears on their account, while the quorum is
what authorises Axal-initiated signing. Setting the quorum as `owner_id` instead would
take the wallet away from the user.

**Repeat calls return the existing wallet.** A duplicate wallet is not a failed
request that can be retried away — it is a second address that may already have
received money, with no way to tell which one the user's funds went to. Four
guards stack, so none has to be perfect on its own:

1. a singleflight group keyed on the external ID collapses concurrent callers
   within an enclave into a single create;
2. the create is skipped when the user already holds a wallet with that external ID;
3. the wallet is looked up directly as `GET /v1/wallets/ext_wal_<external_id>`, which
   answers whether one exists regardless of what the user record shows;
4. Privy receives a deterministic `privy-idempotency-key`, and the external ID is unique
   per app, so a duplicate create collides server side rather than quietly producing a
   second funded address.

Guards 3 and 4 are the ones that hold across instances, and guard 3 is the only one
that does not depend on Privy echoing our `external_id` back inside `linked_accounts`.
Guard 2 alone is not enough for exactly that reason: when the echo is missing, a user
who already holds the wallet is indistinguishable from one who does not.

Guard 4 also has a sharp edge worth knowing: **Privy caches `4xx` and `5xx` responses
against the idempotency key and replays them for 24 hours.** A create that failed on the
way back therefore answers every retry with the same cached error, while the wallet it
made sits there. So a create error is never reported before guard 3 has been asked
whether a wallet exists — the external ID, not the idempotency key, is the durable
duplicate guard.

**These wallets are not embedded HD wallets, and they are not in `linked_accounts`.**
Privy answers the create with `owner_id` set to a key quorum it derived from the
`owner.user_id` we sent, and the wallet is owned by that quorum rather than linked to the
user the way their wallet at index 0 is. It does not appear on `GET /v1/users/{id}` at all.
Two consequences, both load bearing:

- **`wallet_index` is not meaningful for a purpose wallet.** Only the user's embedded
  wallet has an HD index. The field is present in the response because the shape is shared
  with `linked_accounts` entries, and it is zero — do not read it as "this is wallet 0".
- **Signing cannot resolve these wallets from the user record**, so it resolves the address
  at Privy with `POST /v1/wallets/address` and falls back to that whenever an address is
  not on the record. The resolved wallet is folded into the cached record, so the next
  signature for it is a cache hit.

That second point moves the ownership check, which is the part to be careful about.
Resolving by address means an authenticated user can name any address in the app, and the
user record — which used to be the proof that a wallet was theirs — cannot speak for a
quorum-owned wallet. The `external_id` stands in for it: the enclave assigns it as
`<privy DID subject>-<purpose>`, Privy holds external IDs unique per app and write-once, so
an id carrying this user's subject means this enclave provisioned that wallet for them and
no one else can have claimed it. The purpose is round-tripped back through the same
derivation rather than prefix-matched, so there is one definition of the mapping.

Two things are therefore asserted before any wallet is returned or signed with, and they
are the same two in both paths, from one function:

1. **Axal's key quorum is among the wallet's `additional_signers`, on `ethereum`.** This is
   what `POST /v1/wallets/{id}/rpc` checks, so without it the wallet serves user-initiated
   signing and fails every Axal-initiated one — rebalancing, reward claiming — silently, at
   a time nobody is watching.
2. **The `external_id` is one this enclave assigned to this user.** Without it, an
   authenticated user could name any address in the app and be signed for.

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

#### Caching

User records are cached for **2 hours** and the signing path resolves wallet addresses out
of that record, so one cache holds both the user and their wallets — address, HD index,
Privy wallet id, delegation and external id.

Two properties keep the longer TTL honest:

- **Creation writes the record back, it does not evict it.** Provisioning a wallet folds
  the create response into the cached user before returning `200`, so a caller that
  provisions a wallet and immediately signs with it finds the wallet already there. The
  merge works on a copy: `GetUser` hands back a shallow copy whose `LinkedAccounts` slice
  still shares a backing array with the cached entry, so merging in place would mutate the
  cache underneath other readers.
- **Reads do not extend the TTL.** `ttlcache` refreshes an item on every read unless
  disabled. Left on, the users who sign most would be the ones whose record is never
  re-read from Privy, and the TTL would quietly mean forever.

Note that delegation state is cached with everything else, so revoking a wallet's
delegation can take up to the TTL to be reflected here. That is a staleness window, not an
authorization hole: Privy enforces the signer quorum at RPC time, so a revoked wallet is
refused there regardless of what the enclave believes.

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
