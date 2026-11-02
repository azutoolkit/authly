---
description: Complete reference of every setting, store, callback, and TTL on Authly::Configuration.
icon: sliders
---

# `Authly::Configuration`

`Authly.configure { |config| ... }` yields the global `Authly::Configuration` singleton (`Authly.config`).

{% hint style="info" %}
All settings can be inspected at runtime via `Authly.config.<property>` and reset to defaults in tests via `Authly.config.reset!`.
{% endhint %}

---

## Core Issuer & Cryptographic Keys

| Property | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `issuer` | `String` | `"The Authority Server Provider"` | The `iss` claim emitted in JWT access tokens, refresh tokens, ID tokens, and discovery metadata. |
| `base_url` | `String` | `"http://localhost:8080"` | Base URL used to construct endpoint URLs in discovery metadata and fallback `token_audience`. |
| `access_token_audience` | `String?` | `nil` | Explicit `aud` claim emitted on access tokens (`config.token_audience` returns `access_token_audience.presence \|\| base_url.presence`). |
| `secret_key` | `String` | `Random::Secure.hex(16)` | Secret key (for HMAC) or private key PEM (for RSA/ECDSA) used to sign JWTs and anti-CSRF form tokens. |
| `public_key` | `String` | Follows `secret_key` | Verification key (or public key PEM for asymmetric algorithms). |
| `signing_key_id` | `String?` | `nil` | Optional `kid` header attached when signing JWTs. |
| `verification_keys` | `Hash(String, String)` | `{}` | Map of `kid => public_key_pem` for key rotation and JWKS publication. |
| `algorithm` | `JWT::Algorithm` | `JWT::Algorithm::HS256` | JWT signing and verification algorithm. |
| `token_strategy` | `Symbol` | `:jwt` | Token representation strategy: `:jwt` or `:opaque`. |
| `issue_refresh_tokens` (`issue_refresh_tokens?`) | `Bool` | `true` | Whether `AccessToken` issues a `refresh_token` by default. |
| `grant_types` | `Array(String)` | `%w[authorization_code client_credentials password refresh_token implicit urn:ietf:params:oauth:grant-type:device_code challenge_response urn:ietf:params:oauth:grant-type:challenge]` | Enabled OAuth2 grant types. |

---

## Lifetimes (TTLs)

| Property | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `access_ttl` | `Time::Span` | `1.hour` | Access token lifetime (`expires_in`). |
| `refresh_ttl` | `Time::Span` | `1.day` | Individual refresh token lifetime. |
| `refresh_absolute_ttl` | `Time::Span` | `30.days` | Maximum lifetime of an entire refresh token rotation family (`fexp`). |
| `code_ttl` | `Time::Span` | `5.minutes` | Authorization code lifetime. |
| `consent_ttl` | `Time::Span` | `10.minutes` | Consent and device verification anti-CSRF form token lifetime. |
| `par_ttl` | `Time::Span` | `90.seconds` | Pushed Authorization Request (`request_uri`) lifetime. |
| `challenge_ttl` | `Time::Span` | `60.seconds` | Challenge-Response nonce (`challenge_id`) lifetime. |
| `jarm_lifetime` | `Time::Span` | `10.minutes` | JARM response JWT lifetime. |

---

## Stores & Providers

| Property | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `owners` | `Authly::AuthorizableOwner` | `Authly::Owners.new` | Resource owner authenticator and claim provider. |
| `clients` | `Authly::AuthorizableClient` | `Authly::Clients.new` | OAuth2 client authenticator and policy provider. |
| `token_store` | `Authly::TokenStore` | `Authly::InMemoryStore.new` | Token metadata and revocation/consumption store. |
| `state_store` | `Authly::StateStore` | `Authly::InMemoryStateStore.new` | Single-use nonce store for consent and device forms. |
| `device_code_store` | `Authly::DeviceCodeStore` | `Authly::InMemoryDeviceCodeStore.new` | Device authorization state store. |
| `par_store` | `Authly::PARStore` | `Authly::InMemoryPARStore.new` | Pushed Authorization Request store. |
| `challenge_store` | `Authly::ChallengeStore` | `Authly::InMemoryChallengeStore.new` | Challenge-Response store. |
| `client_store` | `Authly::ClientStore` | `Authly::InMemoryClientStore.new` | Dynamically registered client store. |
| `attempt_limiter` | `Authly::AttemptLimiter` | `Authly::InMemoryAttemptLimiter.new` | Rate limiter for device verification lookups. |
| `registration_limiter` | `Authly::AttemptLimiter` | `Authly::InMemoryAttemptLimiter.new` | Rate limiter for failed dynamic client registration attempts. |

---

## Host Callbacks

| Property | Signature | Default | Description |
| :--- | :--- | :--- | :--- |
| `authenticate_user` | `Proc(HTTP::Server::Context, String?)?` | `nil` | Resolves the currently signed-in resource owner's subject ID from the host session. Required for `/oauth/authorize` and `/device`. |
| `login_url` | `Proc(HTTP::Server::Context, String)?` | `nil` | Redirect URL when `authenticate_user` returns `nil` (otherwise responds `401 login_required`). |
| `render_consent` | `Proc(HTTP::Server::Context, AuthorizationRequest, String, String, Nil)?` | `nil` | Optional custom renderer for the `/oauth/authorize` consent page. |
| `userinfo` | `Proc(String, Hash(String, JSON::Any))?` | `nil` | Resolves additional OIDC UserInfo claims for a verified `sub`. |
| `issuance_options` | `Proc(String, String, IssuanceOptions)?` | `nil` | Returns `IssuanceOptions` given `(client_id, grant_type)` at `/oauth/token`. |
| `attempt_source` | `Proc(HTTP::Server::Context, String?)` | Remote socket IP | Identifies the caller source for rate limiting (`attempt_limiter` and `registration_limiter`). |
| `authenticate_registration` | `Proc(HTTP::Server::Context, Bool)?` | `nil` | Custom authenticator for `POST /oauth/register`. |

---

## Security & Protocol Flags

| Property | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enforce_pkce` (`enforce_pkce?`) | `Bool` | `false` | Require PKCE on all authorization code exchanges. |
| `enforce_pkce_s256` (`enforce_pkce_s256?`) | `Bool` | `false` | Require `S256` PKCE method (disallow `plain`). |
| `require_par` (`require_par?`) | `Bool` | `false` | Require Pushed Authorization Requests (`request_uri`) at `/oauth/authorize`. |
| `challenge_max_attempts` | `Int32` | `1` | Maximum verification attempts before a challenge is deleted (`1` = immediate single-attempt invalidation). |
| `device_attempt_limit` | `Int32` | `10` | Max user code lookups at `/device` per owner/source per window. |
| `device_attempt_window` | `Time::Span` | `15.minutes` | Rate-limit window for `/device` lookups. |
| `require_certificate_bound_tokens` (`require_certificate_bound_tokens?`) | `Bool` | `false` | Bind access tokens to client mTLS certificate thumbprints (`cnf.x5t#S256`). |
| `trusted_ca_certificates` | `Array(String)` | `[] of String` | Trusted CA PEMs for mTLS client certificate verification. |
| `allow_dynamic_registration` (`allow_dynamic_registration?`) | `Bool` | `false` | Enable `POST /oauth/register`. |
| `registration_access_token` | `String?` | `nil` | Bearer token required at `POST /oauth/register` (unless `authenticate_registration` is set). |
| `registration_grant_types` | `Array(String)` | `["authorization_code", "refresh_token"]` | Allowed `grant_types` in dynamic client registration. |
| `registration_response_types` | `Array(String)` | `["code"]` | Allowed `response_types` in dynamic client registration. |
| `registration_scopes` | `Array(String)` | `[] of String` | Allowed `scope` values in dynamic client registration. |
| `registration_max_body` | `Int32` | `16384` | Maximum request body size (bytes) for `POST /oauth/register`. |
| `registration_rate_limit` | `Int32` | `10` | Max failed registration auth attempts per source per window. |
| `registration_rate_window` | `Time::Span` | `1.hour` | Rate-limit window for failed registration attempts. |
| `jarm_signing_key` | `String?` | `nil` | Signing key for JARM responses. |
| `jarm_signing_alg` | `JWT::Algorithm` | `JWT::Algorithm::RS256` | Signing algorithm for JARM responses. |
| `jarm_encryption_key` | `String?` | `nil` | Encryption key for JARM JWE responses. |
| `jarm_encryption_alg` | `String?` | `nil` | Key encryption algorithm for JARM JWE responses (e.g., `"RSA-OAEP-256"`). |
| `jarm_encryption_enc` | `String?` | `nil` | Content encryption encoding for JARM JWE responses (e.g., `"A256GCM"`). |
| `default_jarm_response_mode` | `String?` | `nil` | Default JARM `response_mode` (`"query.jwt"`, `"fragment.jwt"`, `"form_post.jwt"`, `"jwt"`). |
