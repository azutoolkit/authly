# Changelog

## [Unreleased] - 2024

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
