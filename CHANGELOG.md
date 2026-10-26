# Changelog

## [Unreleased]

### Security

- **Breaking for custom token generators and old refresh tokens: refresh tokens are validated and rotated (P1-12).**
  A refresh token used to be accepted if it merely decoded: any Authly JWT (an access token, an authorization code),
  a revoked token, and another client's token all passed, and rotation did not exist. Now the token must have
  `token_type: refresh_token`, `cid` equal to the authenticating client, must not be expired or revoked, and is single
  use: it is consumed with `TokenStore#consume` and the answer carries a replacement from the same family (`fid`).
  Presenting a token that was already consumed revokes the whole family (OAuth 2.1 / RFC 6819), so the thief and the
  client both have to sign in again. The refresh token carries the scope of the grant, so a refreshed access token
  keeps it (it used to lose it); the optional `scope` parameter may only narrow it (`invalid_scope` otherwise), and the
  replacement refresh token keeps the original scope. Refresh tokens issued by earlier versions have no `cid`/`fid`/`scope`
  and are refused once: clients sign in again. A custom `TokenGenerator` must override
  `generate_refresh_token(client_id, jti, sub, scope, family)` to emit `cid`, `scope`, `fid` and `token_type`; the default
  keeps compiling but its refresh tokens cannot be redeemed. Access tokens already issued from a revoked family live until
  they expire (`access_ttl`). Opaque-strategy refresh tokens still cannot be redeemed (unchanged)
- `/oauth/userinfo` refuses anything but an access token (`token_type: access_token`): a refresh token or an authorization
  code signed with the same key no longer reads user info
- `Grant#refresh_token_grant` (it could not compile when called) is removed
- **Device flow: guessing and polling are limited (P1-13).** Wrong user codes at `/device` (and wrong `user_code` lookups
  through `GET /device?user_code=`) are counted per signed-in owner and per source; at `Authly.config.device_attempt_limit`
  (10) failures in `device_attempt_window` (15 minutes) the page answers `429` with `Retry-After`, even for a right
  code. The counters live in the new pluggable `Authly.config.attempt_limiter` (`AttemptLimiter`, in-memory and bounded by
  default; share one between nodes); the source is `Authly.config.attempt_source` (the socket address by default: behind a
  reverse proxy return the address your proxy vouches for, or nil to count by account only). User codes are validated
  (`XXXX-XXXX` of the 32-character alphabet; lower case and a missing dash are accepted) before any lookup. Polling faster than `interval`
  is answered `slow_down` and widens the interval by 5 seconds (RFC 8628 3.5; `DeviceCodeData#last_polled_at`); an
  approved device code is redeemed once (it used to mint a token on every poll until it expired) and the token is
  about the owner who approved it (it was anonymous). `InMemoryDeviceCodeStore` is mutex-protected, sweeps expired
  authorizations and keeps at most 50,000. A denied code is deleted, so the device's next poll is `invalid_grant`
- **Breaking: dynamic client registration is no longer anonymous (P1-14).** `POST /oauth/register` (opt-in through
  `allow_dynamic_registration`) registered anyone, with `password`/`implicit`, any scope, any `scheme://host` redirect URI
  (`javascript://x/%0aalert(1)` passed) and an unbounded body. It now needs `Authly.config.registration_access_token`
  (`Authorization: Bearer`, compared in constant time) or `Authly.config.authenticate_registration` (a `Bool` hook), else
  it answers `401` (`500` when neither is configured: nothing is registered). New `RegistrationPolicy` allow-lists:
  `registration_grant_types` (`authorization_code`, `refresh_token`), `registration_response_types` (`code`),
  `registration_scopes` (none, so a `scope` is refused until listed); redirect URIs must be https, loopback http or a
  domain-named private-use scheme, with no fragment, user info or wildcard, at most 10 of at most 2048 characters; the
  other metadata URIs must be https. The body is capped (`registration_max_body`, 16 KiB, `413`) and requests are
  limited per source (`registration_rate_limit` per `registration_rate_window`, `429`; rejected requests count) through
  the new `attempt_limiter`. Malformed metadata answers a fixed message instead of the exception text.
  `DynamicClient#valid?` applies the same URI rules. Secrets were already `Random::Secure`; Authly never reads the
  client store, so no hashing was added
- **Breaking for custom stores:** `DeviceCodeData` has a new `last_polled_at : Time?` (nil when absent from stored JSON);
  a custom `DeviceCodeStore` must keep it when it saves the record, otherwise `slow_down` never triggers

## [1.3.0] - 2026-10-25

Includes the P0 fixes and the consent/authorization hardening (#21). Several changes are breaking for hosts and custom
stores; read "Upgrading" below. Minor rather than major bump: see the pull request for the reasoning.

### Security

- **Breaking: the authorization endpoint authenticates the resource owner through the host.** `/oauth/authorize`
  used to read `user_id` and `consent=approved` from the query string, so anyone could obtain a code for any user
  (and, with the implicit grant, a token with any scope). Set `Authly.config.authenticate_user` (a
  `Proc(HTTP::Server::Context, String?)` returning the signed-in subject id); `user_id` and `consent` are now ignored,
  consent is a POST with a signed, single-use, subject-bound token (`Authly::FormToken`), and until the hook is set the
  endpoint answers 500 and issues nothing. `Authly.config.login_url` (optional) redirects visitors who are not signed in,
  `Authly.config.consent_ttl` sets the form lifetime. See "Upgrading" below
- The requested scope is checked against the client's scopes before a code or an implicit token is issued
  (`invalid_scope` redirect); the redirect URI is matched exactly against the registration before anything is rendered or
  redirected; implicit tokens carry the authenticated subject
- PAR: only the pushed parameters are used at the authorization endpoint (the query can no longer override scope,
  redirect_uri, user_id or consent); `user_id`, `consent` and `client_secret` are not stored with a pushed request
- Reflected XSS fixed on the consent page, the device page and its error page (every value is HTML-escaped); these pages
  send `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` and
  `Referrer-Policy: no-referrer`
- **Breaking: device verification (`/device`) requires `authenticate_user` too.** The approving user is the signed-in owner,
  not a `user_id` form field; the form carries a signed single-use token. Device user codes use `Random::Secure`
- `/oauth/authorize` also routes `POST` in `Authly::Handler`; the `state` parameter is passed through to the client, no
  longer checked against a store the same caller filled

- Pushed `request_uri`s are consumed after the owner is signed in, so PAR works together with `login_url`
- The device page shows the client and scopes behind a user code before the owner approves (RFC 8628 5.4); forms post
  to the path they were served from
- An unknown client, unregistered `redirect_uri` or a grant the client lacks is `400` at the authorization endpoint (was 401);
  a blank scope is `invalid_scope`; `allowed_scopes?` ignores empty tokens from doubled spaces and refuses an empty request
- `form_post.jwt` responses have no inline `onload` handler and are served with a CSP (hash of the one script),
  `X-Frame-Options: DENY` and `Cache-Control: no-store`
- **Breaking for custom stores:** `StateStore#consume` returns `Bool` (true for exactly one caller of a stored, unexpired
  state) and is the only check the handlers make. `InMemoryStateStore` is mutex-protected and sweeps expired entries as it
  grows. With several nodes share `secret_key` and `state_store` (see README)
- The subject returned by `authenticate_user` is stripped

- **Breaking for custom stores:** `PARStore#consume` returns `Bool` too and is the only gate for a pushed `request_uri`
  (`InMemoryPARStore` is mutex-protected); `StateStore#valid?` stays in the interface but no handler calls it.
  `InMemoryStateStore` keeps at most 10,000 live nonces (oldest dropped first) and sweeps expired ones only from 256 entries up
- `allowed_scopes?` is shared with the token endpoint (`validate_scope!`): doubled spaces in a code's scope are accepted there
  too; an empty scope at the token endpoint behaves as before
- The "Try again" link of the device error page is relative; `Clients#delete(client_id)` added

### Upgrading

Hosts that mount `Authly::Handler` (or call `AuthorizationHandler` / `DeviceVerificationHandler`) must configure the hook:

```crystal
Authly.configure do |config|
  config.authenticate_user = ->(context : HTTP::Server::Context) { session_user_id(context) } # String? (nil: nobody)
  config.login_url = ->(context : HTTP::Server::Context) { "/login?return_to=#{URI.encode_www_form(context.request.resource)}" }
end
```

Clients and tests that sent `consent=approved&user_id=...` must stop: the consent page now has to be approved by the
signed-in owner (POST with `consent_token` and `decision=approve|deny`). Hosts that call `Authly.code` themselves (not
through `AuthorizationHandler`) are unaffected.

Summary of what to check when moving from 1.2.x:

- `Authly.config.authenticate_user` must be set, or `/oauth/authorize` and `/device` answer 500 and issue nothing
- An unregistered `redirect_uri`, an unknown client or a grant the client lacks is now `400` (was `401`) at the
  authorization endpoint, and nothing is rendered or redirected
- Consent and device approval are POSTs carrying a signed, single-use, subject-bound `Authly::FormToken`
  (`consent_token`, `decision=approve|deny`); `user_id` and `consent` query parameters are ignored
- Custom `StateStore` and `PARStore` implementations: `consume` returns `Bool` (true for exactly one caller) and is the only
  call the handlers make

### Changed

#### Resource-server hardening

- `Bearer` and `RequireScope` protect every path by default; `except:` lists open paths and `prefixes:` is now
  an allowlist with a documented warning. Paths are percent-decoded, `//`-collapsed and dot-resolved before
  matching (`Authly::Handler::PathFilter`); `/api/` covers `/api`; `prefixes: []` is refused
- A token store that fails (Redis down) gives 503 + `Retry-After` instead of 401; `Authly::VerificationUnavailable`
- Access tokens carry `aud` (`config.access_token_audience`, `base_url` by default) and `token_type`;
  `StrategyTokenVerifier` requires `token_type: "access_token"` (`legacy_tokens: true` for older tokens) and
  enforces `audience:`; refresh tokens carry `token_type: "refresh_token"`
- `StrategyTokenVerifier` honors the configuration it is given and decodes the token once
- `except_exact:` exempts one path only; `except:` is documented as a case-sensitive segment-prefix match. Paths with a `%` left
  after decoding, or a NUL byte, are protected. `RequireScope` takes `pass_preflight:` too
- `Authly::StoreUnavailable` (and `IO::Error`) mean 503; any other exception from a token store is an invalid token, not an outage
- Blank `base_url`/audience means no `aud` claim; HEAD on JWKS/metadata advertises the GET `Content-Length`
- `context.authly_claims!` raises `Authly::MissingClaims`
- JWKS: the algorithm must fit the key type; the endpoint sets `Cache-Control` only on success (`no-store` on errors)
- `Bearer`: `pass_preflight:` for CORS preflights, repeated `access_token` query values refused, `Cache-Control: private` and
  `Referrer-Policy: no-referrer` on query-token responses
- `OpaqueToken#valid?` no longer turns store errors into "invalid"; `JWTToken#valid?` logs at debug, without token content

### Added

#### Resource Server Handlers

- `Authly::Handler::Bearer`: a plain `HTTP::Handler` that verifies `Authorization: Bearer` tokens (signature
  with the configured algorithm, `exp`, `nbf`, issuer, revocation, optional audience; JWT and opaque
  strategies; access tokens only) and answers failures per RFC 6750 (401/400 with `WWW-Authenticate`)
- `context.authly_claims` (`Authly::Claims`): the verified claims, stored per request context
- `Authly::Handler::RequireScope`: all-of / any-of scope guard, 403 `insufficient_scope`
- `Authly::TokenVerifier` / `Authly::StrategyTokenVerifier`: the verification strategy `Bearer` uses
- `Authly::JWKS` and `GET /.well-known/jwks.json` (RSA and EC public keys with an RFC 7638 `kid`; empty
  for HMAC), `GET /.well-known/oauth-authorization-server` (RFC 8414)

#### Enhanced PKCE with S256 Method Enforcement

- **PKCE Enforcement Configuration**:
  - Added `config.enforce_pkce` to require PKCE for all authorization code flows
  - Added `config.enforce_pkce_s256` to mandate S256 method and reject plain method
  - Validation in `AuthorizationHandler` enforces PKCE requirements when enabled
  - Comprehensive specs for PKCE validation

#### OpenID Connect Discovery Endpoint

- **Discovery Endpoint** (`GET /.well-known/openid-configuration`):
  - Returns complete OpenID Connect discovery metadata
  - Lists supported grant types, scopes, response types, and algorithms
  - Dynamically adjusts PKCE methods based on configuration
  - Includes all authentication endpoints (authorization, token, userinfo, etc.)
  - Added `config.base_url` for constructing absolute URLs

#### UserInfo Endpoint

- **UserInfo Endpoint** (`GET /oauth/userinfo`):
  - Returns user claims based on access token
  - Scope-based claim filtering (openid, profile, email, address, phone)
  - Bearer token authentication via Authorization header
  - Supports both JWT and opaque token strategies
  - Comprehensive error handling for invalid/expired tokens

#### OAuth2 Dynamic Client Registration (RFC 7591)

- **Client Registration Endpoint** (`POST /oauth/register`):
  - Dynamic client registration per RFC 7591
  - Support for public clients (no client_secret when `token_endpoint_auth_method` is "none")
  - Comprehensive metadata validation
  - Added `config.allow_dynamic_registration` flag
  - Created `DynamicClient` struct with full RFC 7591 metadata support
  - Created `ClientStore` interface with `InMemoryClientStore` implementation
  - Validates redirect URIs, grant types, response types, and authentication methods

#### Certificate-Bound Access Tokens (mTLS / RFC 8705)

- **Certificate-Bound Tokens**:
  - Binds access tokens to client TLS certificates
  - Implements RFC 8705 confirmation claim (`cnf` with `x5t#S256` thumbprint)
  - Added `config.require_certificate_bound_tokens` flag
  - Added `config.trusted_ca_certificates` for CA validation
  - Created `CertificateValidator` module for certificate extraction and validation
  - Created `TokenBinder` module for thumbprint extraction and verification
  - Updated `TokenGenerator` to include certificate thumbprints in tokens
  - Works with both JWT and opaque token strategies
  - Prevents token theft - stolen tokens cannot be used without the bound certificate

### Fixed

#### Critical Bugs

- **Filename Typos**: Renamed `introspect_hanlder.cr` and `revoke_hanlder.cr` to correct spelling (`introspect_handler.cr`, `revoke_handler.cr`)
- **SecureRandom Usage**: Fixed `SecureRandom.hex()` to use `Random::Secure.hex()` (Crystal stdlib)

#### Security Vulnerabilities

- **State Store Replay Attack Prevention**:
  - Added expiration time to state store entries (configurable TTL, default 5 minutes)
  - Implemented state consumption after successful use to prevent replay attacks
  - Added `consume()` method to StateStore interface
  - Added `cleanup_expired()` method for removing stale states

#### Grant Factory

- Fixed inconsistent parameter types in `GrantFactory.create` (now consistently uses `.to_s`)
- Standardized parameter handling across all grant types

### Added

#### Opaque Token Support

- **Token Generator Strategy Pattern**:

  - Created `TokenGenerator` module with pluggable token generation strategies
  - Implemented `JWTTokenGenerator` (existing JWT behavior)
  - Implemented `OpaqueTokenGenerator` (random secure hex tokens with metadata storage)
  - Token strategy selected via `config.token_strategy` (`:jwt` or `:opaque`)

- **Token Storage**:
  - Opaque tokens store metadata in `token_store` with expiration
  - Updated `OpaqueToken` introspection to return OAuth2-compliant format
  - Support for both access and refresh opaque tokens

#### Device Code Grant (RFC 8628)

- **New Grant Type**: `urn:ietf:params:oauth:grant-type:device_code`
- **Device Code Store**: In-memory implementation with user code indexing
- **Endpoints**:
  - `POST /oauth/device/code` - Request device and user codes
  - `GET /device` - User verification page
  - `POST /device` - User approval/denial
- **Features**:
  - User-friendly 8-character codes (e.g., "ABCD-1234")
  - Configurable expiration (default 15 minutes)
  - Polling interval support
  - Authorization pending/slow down error handling

#### Implicit Grant

- **Proper Implementation**: `response_type=token` now works correctly
- **Fragment-based Redirect**: Access tokens returned in URI fragment (per OAuth2 spec)
- **Authorization Handler**: Updated to support both code and token response types

#### Enhanced Error Handling

- Added `authorization_pending` error for device code flow
- Added `slow_down` error for polling rate limiting
- Added `expired_token` error for expired device codes
- Improved error messages with OAuth2-compliant responses

### Improved

#### Configuration

- Added `device_code_store` property (default: `InMemoryDeviceCodeStore`)
- Added `state_store` TTL configuration support
- Better separation of concerns for different stores

#### Authorization Handler

- Support for multiple response types (`code`, `token`)
- Proper URL encoding for redirect parameters
- Fragment-based redirects for implicit flow
- State consumption after successful authorization

### Testing

#### New Test Suites (30 new tests)

- **State Store Tests** (`spec/state_store_spec.cr`):

  - State storage and validation
  - Expiration handling
  - Replay attack prevention
  - Cleanup of expired states

- **Device Code Grant Tests** (`spec/grants/device_code_spec.cr`):

  - Device authorization creation
  - User code format validation
  - Authorization flow
  - Store operations

- **Token Strategy Tests** (`spec/token_strategy_spec.cr`):

  - JWT token generation and validation
  - Opaque token generation and validation
  - Token storage and retrieval
  - Token revocation for both strategies
  - Introspection for both strategies

- **Implicit Grant Tests** (`spec/grants/implicit_spec.cr`):
  - Token response type
  - Redirect URI validation
  - Client authorization

#### Test Results

- **Total Tests**: 80 (up from 50)
- **Passing**: 70 unit tests
- **Failing**: 10 integration tests (require running server, pre-existing issue)

### Technical Details

#### Type System Improvements

- Added `TokenPayload` type alias for token store values
- Improved type safety in token generation
- Better nil handling in introspection

#### Code Quality

- Consistent parameter handling across grants
- Better separation of JWT and opaque token logic
- Cleaner error handling with rescue clauses

## Migration Guide

### For Existing Users

1. **No Breaking Changes**: All existing code continues to work
2. **New Features Available**:

   ```crystal
   # Enable opaque tokens
   Authly.configure do |config|
     config.token_strategy = :opaque
   end

   # Device code flow
   # 1. Client requests device code
   POST /oauth/device/code

   # 2. User visits /device and enters code

   # 3. Client polls for token
   POST /oauth/token
     grant_type=urn:ietf:params:oauth:grant-type:device_code
     device_code=...
   ```

3. **Security Improvements**: State replay attacks now prevented automatically

### For Contributors

- Run tests: `crystal spec`
- All unit tests should pass (70/70)
- Integration tests require test server: `crystal spec/support/test_server.cr`
