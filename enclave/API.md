# Enclave API

Wire contract for the enclave's HTTP API, as served through the host's VSOCK proxy.

This document covers the routes that changed for multi-wallet support, plus the new
wallet provisioning route. For what the enclave *is*, see [README.md](README.md);
for caching behaviour, see the Caching section there.

- [Conventions](#conventions)
- [Wallet selection](#wallet-selection)
- [GET /api/v1/user](#get-apiv1user)
- [POST /api/v1/user/wallet](#post-apiv1userwallet)
- [POST /api/v1/user/signer/eth/secp256k1Sign](#post-apiv1usersignerethsecp256k1sign)
- [POST /api/v1/axal/signer/eth/secp256k1Sign](#post-apiv1axalsignerethsecp256k1sign)
- [POST /api/v1/axal/signer/eth/personalSign](#post-apiv1axalsignerethpersonalsign)
- [HMAC reference](#hmac-reference)
- [Errors](#errors)

---

## Conventions

Every request sends `Content-Type: application/json` and an **`auth`** header. What goes
in `auth` depends on the route:

| Route group | `auth` contains |
|---|---|
| `/api/v1/user/**` | The user's Privy JWT |
| `/api/v1/axal/**` | `hex(HMAC_SHA256(sharedSecret, preimage))` — see [HMAC reference](#hmac-reference) |

Errors are always a single-field object, whatever the status:

```jsonc
{ "message": "requested wallet is not a delegated eth wallet for this user" }
```

Errors originating at Privy are passed through with Privy's own status code and message,
so a 4xx body may carry text this document does not list.

---

## Wallet selection

A user may hold several delegated EVM wallets — one per pot of money, so balances and PnL
can be tracked apart. **Every signing route therefore requires a `wallet_address`.**

- **Format.** Send lowercase, `0x`-prefixed hex: `0xabcdef0123456789abcdef0123456789abcdef01`.
  Comparison is case-insensitive, but the HMAC preimage assumes lowercase.
- **No default.** The enclave never infers a signer. A missing, empty, or malformed
  address is rejected before authentication runs.
- **No fallback.** The address must resolve to a delegated `ethereum` wallet belonging to
  the authenticated user — the JWT's user on `/user` routes, the `privy_id` in the body on
  `/axal` routes. An address that is unknown or belongs to someone else is rejected rather
  than served by a different wallet, because a signature from the wrong key produces a user
  operation that fails validation on chain.
- **Authenticated, not asserted.** On the Axal routes the address is part of the HMAC
  preimage, so a modified request body cannot redirect a signature to another of the user's
  wallets.

Addresses are the wire format rather than Privy wallet ids because an address can be
*verified* against the user's linked accounts. The enclave resolves the address to a Privy
wallet id internally and signs through `POST /v1/wallets/{wallet_id}/rpc`.

---

## GET /api/v1/user

Returns the authenticated Privy user. Creates the user's first embedded wallet if they do
not have one, so it is safe to call at signup.

**Auth:** user Privy JWT.

### Response `200`

```jsonc
{
  "id": "did:privy:cm00000000000000000001",
  "created_at": 1234567890,
  "linked_accounts": [
    {
      "id": "kx7p2m9q4w1e8r5t",      // privy wallet id
      "type": "wallet",
      "address": "0xaaaa000000000000000000000000000000000001",
      "chain_type": "ethereum",
      "wallet_index": 0,
      "delegated": true
    },
    {
      "id": "nb3v6c8x2z5l9k4j",
      "type": "wallet",
      "address": "0xbbbb000000000000000000000000000000000002",
      "chain_type": "ethereum",
      "wallet_index": 1,
      "delegated": true,
      "external_id": "cm00000000000000000001-wealth_plan"
    }
  ],
  "mfa_methods": [],
  "has_accepted_terms": true,
  "is_guest": false
}
```

> **Changed.** `wallet_index` and `delegated` are now always present. They were previously
> tagged `omitempty`, which silently dropped `wallet_index` for wallet 0 and `delegated`
> when false — so wallet 0 read as having no index at all. `external_id` is new and appears
> only on wallets that carry one.

`linked_accounts` also carries non-wallet accounts such as email. `address` is shared
between both kinds, so filter on `chain_type` before treating an entry as a wallet.

---

## POST /api/v1/user/wallet

Provisions an additional delegated EVM wallet for the authenticated user and returns it.

**Auth:** user Privy JWT.

### Request

```jsonc
{ "purpose": "wealth_plan" }
```

| Field | Type | Notes |
|---|---|---|
| `purpose` | string | Required. `^[a-z][a-z0-9_-]{0,31}$` — lowercase, no dots. |

Wallets are named by **purpose, not HD index**. Privy's server API treats `wallet_index`
as read-only on the wallet it returns — only its client SDK can pin an index — so an index
parameter would name something the enclave cannot honour. The purpose maps to a stable
Privy external id of `<privy DID subject>-<purpose>`, which is what identifies the wallet
on every later call. The charset is narrower than it looks because that external id is
restricted to `[a-zA-Z0-9_-]` and capped at 64 characters.

### Response `200`

The created wallet, in the same shape as a `linked_accounts` entry:

```jsonc
{
  "id": "nb3v6c8x2z5l9k4j",
  "type": "wallet",
  "address": "0xbbbb000000000000000000000000000000000002",
  "chain_type": "ethereum",
  "wallet_index": 1,
  "delegated": true,
  "external_id": "cm00000000000000000001-wealth_plan"
}
```

`delegated: true` is asserted before the wallet is returned rather than assumed — a wallet
created without the enclave's signer attached would serve user-initiated signing and fail
every Axal-initiated one.

### Repeat calls are safe

**Asking twice for the same purpose returns the same wallet.** A duplicate wallet is not a
failed request that can be retried away; it is a second address that may already have
received money. Four guards stack, so none has to be perfect alone:

| Guard | Covers | Scope |
|---|---|---|
| Singleflight on the external id | Concurrent callers collapse into one create | This enclave |
| Read-before-create | The user already holds a wallet with that external id | This enclave |
| `GET /v1/wallets/ext_wal_<external_id>` | A wallet exists under the external id, whatever the user record shows | Across instances |
| `privy-idempotency-key` + unique `external_id` | Retries this process never sees | Across instances |

The third guard is the only one that does not depend on Privy echoing `external_id` back
inside `linked_accounts`, which is why it is worth an extra round trip. It is also what makes
a create error safe to doubt: Privy caches `4xx` and `5xx` responses against the idempotency
key and **replays them for 24 hours**, so a create that failed on the way back would
otherwise answer every retry with the same cached error while the wallet it made sits
unused. The external id — unique per app — is the durable duplicate guard, not the
idempotency key.

### Upstream endpoint

The wallet is created on Privy's wallet API, `POST /v1/wallets`, with `owner` set to the
user and the enclave's key quorum attached as an `additional_signer`:

```jsonc
{
  "chain_type": "ethereum",
  "external_id": "cm00000000000000000001-wealth_plan",
  "owner": { "user_id": "did:privy:cm00000000000000000001" },
  "additional_signers": [ { "signer_id": "<delegated actions key id>" } ]
}
```

Not `POST /v1/users/{user_id}/wallets`. That endpoint provisions the embedded wallet a user
does not yet have and answers `200` **without creating anything** for a chain type the user
already holds, so requests for a second wallet succeeded while minting nothing. Owner and
additional signer are distinct roles and both matter: the user owns the wallet, so it is
theirs and appears on their account, while the quorum is what authorises Axal-initiated
signing on `POST /v1/wallets/{id}/rpc`. Passing the quorum as `owner_id` instead would take
the wallet away from the user.

### These wallets are not in `linked_accounts`

Privy answers the create with `owner_id` set to a key quorum derived from `owner.user_id`, and
the wallet is owned by that quorum rather than linked to the user like their wallet at index 0.
It does not appear on `GET /v1/users/{id}`.

So **`wallet_index` is not meaningful for a purpose wallet.** It is present because the
response shape is shared with `linked_accounts` entries, and it is `0` — do not read it as
"this is wallet 0". Identify these wallets by `id`, `address`, or `external_id`.

`delegated: true` in the response is asserted, not copied: Privy reports no `delegated` flag
for a quorum-owned wallet, and what the flag means throughout the enclave is "Axal can sign
for this".

### Signing with one

`POST /api/v1/user/sign/*` names a wallet by address. Because a purpose wallet is absent from
the user record, an address that is not found there is resolved at Privy with
`POST /v1/wallets/address`, and the resolved wallet is cached on the user so the next signature
for it is a cache hit. Wallet 0 still resolves from the record with no lookup.

Resolving by address means an authenticated user can name any address in the app, so two
assertions guard every wallet — the same two at provisioning and at signing:

| Assertion | Without it |
|---|---|
| Axal's quorum is among the wallet's `additional_signers`, on `ethereum` | The wallet serves user-initiated signing and fails every Axal-initiated one, silently |
| `external_id` is one this enclave assigned to this user | An authenticated user could name any address in the app and be signed for |

The second is the ownership check. The enclave assigns `external_id` as
`<privy DID subject>-<purpose>` and Privy holds external IDs unique per app and write-once, so
an id carrying this user's subject means this enclave provisioned that wallet for them. The
purpose is round-tripped through the same derivation rather than prefix-matched, so a crafted
id cannot satisfy a looser version of the rule.

The wallet is also written into the user cache before this call returns, so a caller that
provisions a wallet and immediately signs with it will find it.

### Ordering

Privy requires a wallet at HD index 0 to exist before creating one at a higher index. This
route reads the user first, which creates wallet 0 if it is missing, so there is no
ordering requirement on the caller.

---

## POST /api/v1/user/signer/eth/secp256k1Sign

Signs a 32-byte hash with a wallet the authenticated user holds. Used for user-initiated
actions — deposits, withdrawals, trades.

**Auth:** user Privy JWT.

### Request

```jsonc
{
  "method": "secp256k1_sign",
  "params": { "hash": "0x..." },
  "wallet_address": "0xbbbb000000000000000000000000000000000002"
}
```

| Field | Type | Notes |
|---|---|---|
| `method` | string | Required. Must be `"secp256k1_sign"`. |
| `params.hash` | string | Required. The hash to sign. |
| `wallet_address` | string | **Required.** Must be a delegated eth wallet of the JWT's user. |

> **Changed.** `wallet_address` is new and required. A request without it is rejected with
> `400`; there is no wallet-0 default.

### Response `200`

```jsonc
{ "method": "secp256k1_sign", "data": { "signature": "0x...", "encoding": "hex" } }
```

---

## POST /api/v1/axal/signer/eth/secp256k1Sign

Signs a 32-byte hash on Axal's initiative — rebalancing, reward claiming, disbursements.
No user session exists for these, so the caller names the user.

**Auth:** HMAC over the [3-part preimage](#hmac-reference).

### Request

```jsonc
{
  "privy_id": "did:privy:cm00000000000000000001",
  "method": "secp256k1_sign",
  "params": { "hash": "0x..." },
  "wallet_address": "0xbbbb000000000000000000000000000000000002"
}
```

| Field | Type | Notes |
|---|---|---|
| `privy_id` | string | Required. The user whose wallet signs. |
| `method` | string | Required. Must be `"secp256k1_sign"`. |
| `params.hash` | string | Required. |
| `wallet_address` | string | **Required.** Must be a delegated eth wallet of `privy_id`. |

> **Changed.** `wallet_address` is new and required, **and the HMAC preimage changed with
> it.** A request carrying the old 2-part preimage is rejected.

### Response `200`

```jsonc
{ "method": "secp256k1_sign", "data": { "signature": "0x...", "encoding": "hex" } }
```

---

## POST /api/v1/axal/signer/eth/personalSign

Signs an EIP-191 personal message with a wallet the named user holds.

**Auth:** HMAC over the [personal-sign preimage](#hmac-reference).

### Request

```jsonc
{
  "privy_id": "did:privy:cm00000000000000000001",
  "method": "personal_sign",
  "params": { "message": "…", "encoding": "utf-8" },
  "wallet_address": "0xbbbb000000000000000000000000000000000002",
  "purpose": "account_link"
}
```

| Field | Type | Notes |
|---|---|---|
| `privy_id` | string | Required. |
| `method` | string | Required. Must be `"personal_sign"`. |
| `params.message` | string | Required. Up to 16 KiB decoded. |
| `params.encoding` | string | Required. `"utf-8"` or `"hex"`. |
| `wallet_address` | string | Required. Was already required on this route. |
| `purpose` | string | Required. `^[a-z][a-z0-9_.-]{0,63}$`. |

The request contract is unchanged, but the route now resolves `wallet_address` against
**all** of the user's delegated wallets. It previously accepted only the first one, so it
would have rejected every wallet beyond wallet 0.

Callers remain responsible for any use-case-specific message or challenge validation before
requesting a signature. Raw messages and signatures are not logged.

### Response `200`

```jsonc
{ "method": "personal_sign", "data": { "signature": "0x...", "encoding": "hex" } }
```

---

## HMAC reference

`auth` on the Axal routes is `hex(HMAC_SHA256(sharedSecret, preimage))`. Fields are joined
with `:`, and the wallet address is **lowercased** before joining.

### `secp256k1Sign`

```
hash + ":" + privyId + ":" + walletAddress
```

> **Changed** from `hash + ":" + privyId`. The wallet is part of the preimage so that it is
> authenticated rather than merely asserted: without it, anyone able to modify the body in
> flight could redirect a signature to another of the user's wallets. There is one accepted
> form — a request computed over the old 2-part preimage does not validate.

### `personalSign`

```
method + ":" + purpose + ":" + encoding + ":" + lower(walletAddress) + ":" + hex(sha256(message)) + ":" + privyId
```

The message is hashed rather than included, so no raw message reaches an HTTP header or a
log line.

---

## Errors

| Status | `message` | Meaning |
|---|---|---|
| `401` | `Unauthorized user` | No `auth` header on a `/user` route. |
| `401` | `Unauthorized User` | JWT invalid, expired, or not for this app. |
| `401` | `Missing HMAC signature` | No `auth` header on an `/axal` route. |
| `401` | `Unauthorized User - Invalid HMAC` | HMAC did not verify against the expected preimage. |
| `400` | `tx data is invalid` | Malformed body, wrong `method`, missing `hash`, or missing/malformed `wallet_address` on a `secp256k1Sign` route. |
| `400` | `signing data is invalid` | The same, for `personalSign` — including an unsupported encoding or an empty or oversized message. |
| `400` | `wallet request is invalid` | Malformed body or invalid `purpose` on the wallet route. |
| `400` | `purpose is invalid` | The purpose cannot form a valid Privy external id. |
| `400` | `requested wallet is not a delegated eth wallet for this user` | The address is unknown, undelegated, on another chain, or belongs to a different user. |
| `500` | `Internal Server Error` | Privy call failed, or a created wallet came back undelegated. |

A rejected signing request never produces a signature — there is no partial success and no
substitute wallet.
