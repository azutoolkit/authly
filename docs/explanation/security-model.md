---
description: How Authly prevents TOCTOU replay attacks, timing side-channels, algorithm confusion, and resource exhaustion.
icon: shield-check
---

# Security Model & Multi-Node Deployment

Authly's security design follows **RFC 6749**, **RFC 6750**, **OAuth 2.0 Security Best Current Practice (RFC 9700)**, and **FAPI** principles.

---

## 1. Atomic Single-Use Credentials

Several credentials in OAuth2 must be **strictly single-use**:
- Authorization codes (`jti` in `TokenStore#consume`)
- Refresh tokens (`jti` in `TokenStore#consume`)
- Pushed Authorization Request URIs (`request_uri` in `PARStore#consume`)
- Consent & Device form CSRF tokens (`state` in `StateStore#consume`)
- Cryptographic challenges (`challenge_id` in `ChallengeStore#consume!` / `record_attempt!`)

{% hint style="danger" %}
### Why Check-Then-Delete Is Insecure
A naive implementation that checks `if store.valid?(id)` and later calls `store.delete(id)` is vulnerable to a race condition (TOCTOU): two parallel requests presenting the same authorization code or challenge nonce can both pass `valid?` before either executes `delete`.
{% endhint %}

Authly's handlers **never** call `valid?` followed by `delete`. Instead, they rely on a single atomic operation (`consume` / `consume!` / `record_attempt!`).
- In Authly's in-memory stores, this atomicity is enforced with a `Mutex`.
- In multi-node Redis or SQL stores, implement `consume` as a single atomic command (e.g., Redis `SET key 1 NX EX ttl`, `DEL key` returning `1`, or `GETDEL key`).

---

## 2. Cryptographic Challenge-Response Hardening

Authly's Challenge-Response grant (`challenge_response` / `urn:ietf:params:oauth:grant-type:challenge`) defends against credential replay, timing side-channels, and brute-force guessing:

1. **High-Entropy Nonces**: Challenges are 256-bit random values generated with `Random::Secure.hex(32)` and expire after `config.challenge_ttl` (`60.seconds` by default).
2. **Client Binding**: Each challenge is bound to the `client_id` that requested it at `POST /oauth/challenge`. Presenting a valid signature under a different `client_id` fails with `invalid_grant` and immediately burns the challenge.
3. **Constant-Time HMAC Verification**: Symmetric challenge responses (`HMAC-SHA256`, `HMAC-SHA384`, `HMAC-SHA512`) are compared using `Crypto::Subtle.constant_time_compare` so attackers cannot infer digest bytes via response timing.
4. **Immediate Burn on Attempt**: With the default `config.challenge_max_attempts = 1`, the challenge is removed from `ChallengeStore` on the very first verification attempt—whether the signature is valid or invalid.

---

## 3. Algorithm Confusion & Key Separation

- **JOSE Header `alg` Is Never Trusted**: When decoding JWTs, Authly verifies signatures exclusively against `Authly.config.algorithm`. Tokens carrying `"alg": "none"` or attempting RSA-to-HMAC public-key confusion are rejected.
- **Public Key Validation in JWKS**: `Authly::JWKS` parses DER SubjectPublicKeyInfo structures and verifies that the public key type and curve match `config.algorithm` (`RS*` requires RSA; `ES256`/`ES384`/`ES512` require P-256/P-384/P-521). Private keys are refused outright so a misconfigured `public_key` can never leak private key material at `/.well-known/jwks.json`.

---

## 4. Fail-Closed Rate Limiting & Bounded In-Memory Stores

Endpoints reachable before authentication or with short user codes (`/oauth/device/code`, `/device`, `/oauth/challenge`, `/oauth/register`) are targets for resource exhaustion and brute-force attacks:
- **Bounded In-Memory Stores**: `InMemoryStateStore`, `InMemoryDeviceCodeStore`, `InMemoryChallengeStore`, and `InMemoryAttemptLimiter` enforce strict `MAX_ENTRIES` caps and sweep expired entries periodically during writes.
- **Fail-Closed Rate Limiter**: `InMemoryAttemptLimiter` never evicts a live rate-limit counter to make room for new keys (which would allow an attacker to reset their own counter by flooding the limiter from spoofed keys). If all `MAX_ENTRIES` slots are occupied by live counters, new keys return `Int32::MAX` (`FULL`), causing the endpoint to reject requests until existing windows expire.

---

## 5. Multi-Node Deployment Checklist

When running multiple instances of an Authly server behind a load balancer:
- [ ] Configure the exact same `config.secret_key` (and `config.public_key` / `config.verification_keys`) on every node.
- [ ] Replace all in-memory stores (`token_store`, `state_store`, `challenge_store`, `par_store`, `device_code_store`, `client_store`) with shared Redis or database implementations.
- [ ] Replace `attempt_limiter` and `registration_limiter` with a shared atomic Redis `AttemptLimiter`.
- [ ] Configure `config.attempt_source` to read the client IP header overwritten by your reverse proxy (e.g., `X-Real-IP`), and ensure the application is only reachable through that proxy.
