# Changelog

## [Unreleased] - 2024

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
