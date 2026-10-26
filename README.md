# Authly

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/747eef2e02594d40b63c9f05c6b94cd9)](https://app.codacy.com/manual/eliasjpr/authly?utm_source=github.com&utm_medium=referral&utm_content=eliasjpr/authly&utm_campaign=Badge_Grade_Settings) [![Crystal CI](https://github.com/azutoolkit/authly/actions/workflows/crystal.yml/badge.svg)](https://github.com/azutoolkit/authly/actions/workflows/crystal.yml)

<div align="center">
  <img src="https://raw.githubusercontent.com/azutoolkit/authly/master/authly.png" alt="Authly Logo" />
  <p><strong>A robust OAuth2 and OpenID Connect authentication library for Crystal</strong></p>
</div>

Authly is a production-ready Crystal library that provides secure, standards-compliant OAuth2 and OpenID Connect authentication capabilities. Built with developer experience in mind, Authly offers a comprehensive suite of grant types, flexible token strategies, and intuitive APIs that make implementing authentication straightforward and maintainable.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [OAuth2 Grant Types](#oauth2-grant-types)
- [Authentication Endpoints](#authentication-endpoints)
- [Customization](#customization)
  - [Custom Authorizable Client](#custom-authorizable-client)
  - [Custom Authorizable Owner](#custom-authorizable-owner)
  - [Custom Token Store](#custom-token-store)
- [Token Strategies](#token-strategies)
- [Protecting Your API](#protecting-your-api)
  - [Bearer Handler](#bearer-handler)
  - [Requiring Scopes](#requiring-scopes)
  - [JWKS and Metadata](#jwks-and-metadata)
  - [Mounting in an Azu App](#mounting-in-an-azu-app)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Features

Authly provides a comprehensive authentication solution with the following capabilities:

**OAuth2 Grant Types**

- ✅ Authorization Code Grant (with PKCE support)
- ✅ Client Credentials Grant
- ✅ Resource Owner Password Credentials Grant
- ✅ Implicit Grant
- ✅ Refresh Token Grant
- ✅ Device Authorization Grant

**OpenID Connect**

- ✅ ID Token generation and validation
- ✅ Standard claims support
- ✅ Custom claims integration
- ✅ UserInfo endpoint
- ✅ OpenID Connect Discovery (/.well-known/openid-configuration)
- ✅ OAuth2 Dynamic Client Registration (RFC 7591)

**Token Management**

- ✅ JWT and Opaque token strategies
- ✅ Token introspection endpoint
- ✅ Token revocation endpoint
- ✅ Configurable token expiration (TTL)
- ✅ Pluggable token storage backend

**Security**

- ✅ PKCE (Proof Key for Code Exchange) support with S256 enforcement
- ✅ Certificate-bound access tokens (mTLS / RFC 8705)
- ✅ JWT Secured Authorization Response Mode (JARM / RFC 9101)
- ✅ State parameter validation
- ✅ Redirect URI validation
- ✅ Secure token generation
- ✅ Multiple JWT algorithms support (HS256, RS256, etc.)

**Developer Experience**

- ✅ Intuitive, type-safe API
- ✅ Comprehensive documentation
- ✅ Easy-to-configure HTTP handlers
- ✅ Flexible customization points
- ✅ Built-in middleware support

## Installation

Add Authly to your `shard.yml`:

```yaml
dependencies:
  authly:
    github: azutoolkit/authly
```

Then run:

```bash
shards install
```

**Requirements:**

- Crystal 1.0 or higher
- A supported operating system (Linux, macOS, or Windows)

## Quick Start

Get up and running with Authly in minutes:

```crystal
require "authly"

# Configure Authly
Authly.configure do |config|
  config.issuer = "https://your-app.com"
  config.secret_key = ENV["AUTHLY_SECRET_KEY"]
  config.access_ttl = 1.hour
  config.refresh_ttl = 1.day
  config.token_strategy = :jwt
  config.algorithm = JWT::Algorithm::HS256
end

# Start the authentication server
server = HTTP::Server.new([
  Authly::Handler.new,
])

server.bind_tcp("0.0.0.0", 8080)
puts "Authly server listening on http://0.0.0.0:8080"
server.listen
```

This minimal setup provides a working OAuth2 server with JWT token support. For production use, you'll want to implement custom clients, owners, and token storage (see [Customization](#customization)).

## Configuration

Authly offers extensive configuration options to tailor authentication to your application's needs:

```crystal
Authly.configure do |config|
  # Issuer Configuration
  config.issuer = "https://your-app.com"
  config.base_url = "https://your-app.com"  # Base URL for OpenID Connect Discovery

  # Security Keys
  config.secret_key = ENV["AUTHLY_SECRET_KEY"]  # Required for JWT signing
  config.public_key = ENV["AUTHLY_PUBLIC_KEY"]  # Optional, for asymmetric algorithms

  # Token Time-to-Live (TTL)
  config.access_ttl = 1.hour      # Access token expiration
  config.refresh_ttl = 1.day      # Refresh token expiration
  config.code_ttl = 5.minutes     # Authorization code expiration

  # Token Strategy
  config.token_strategy = :jwt    # Options: :jwt or :opaque
  config.algorithm = JWT::Algorithm::HS256  # JWT signing algorithm

  # Resource-owner login (REQUIRED for /oauth/authorize and /device, see "Authorization Endpoint")
  config.authenticate_user = ->(context : HTTP::Server::Context) { MySession.user_id(context) }
  config.login_url = ->(context : HTTP::Server::Context) { "/login?return_to=#{URI.encode_www_form(context.request.resource)}" }

  # PKCE Enforcement
  config.enforce_pkce = false           # Require PKCE for all authorization code flows
  config.enforce_pkce_s256 = false      # Enforce S256 method only (reject plain)

  # Dynamic Client Registration
  config.allow_dynamic_registration = false
  config.client_store = InMemoryClientStore.new

  # Certificate-Bound Tokens (mTLS)
  config.require_certificate_bound_tokens = false
  config.trusted_ca_certificates = [] of String

  # Custom Implementations (see Customization section)
  config.owners = CustomAuthorizableOwner.new
  config.clients = CustomAuthorizableClient.new
  config.token_store = CustomTokenStore.new
  config.state_store = CustomStateStore.new
  config.device_code_store = CustomDeviceCodeStore.new
end
```

### Configuration Options

| Option           | Type               | Description                          | Default     |
| ---------------- | ------------------ | ------------------------------------ | ----------- |
| `issuer`         | String             | The issuer identifier for tokens     | Required    |
| `secret_key`     | String             | Secret key for JWT signing           | Required    |
| `public_key`     | String             | Public key for asymmetric algorithms | `nil`       |
| `access_ttl`     | Time::Span         | Access token lifetime                | `1.hour`    |
| `refresh_ttl`    | Time::Span         | Refresh token lifetime               | `1.day`     |
| `refresh_absolute_ttl` | Time::Span   | Longest a sign-in can be renewed by rotating refresh tokens | `30.days` |
| `code_ttl`       | Time::Span         | Authorization code lifetime          | `5.minutes` |
| `token_strategy` | Symbol             | Token type (`:jwt` or `:opaque`)     | `:jwt`      |
| `algorithm`      | JWT::Algorithm     | JWT signing algorithm                | `HS256`     |
| `owners`         | AuthorizableOwner  | Resource owner authentication        | Required    |
| `clients`        | AuthorizableClient | Client authentication                | Required    |
| `token_store`    | TokenStore         | Token persistence layer              | In-memory   |

## OAuth2 Grant Types

Authly implements all standard OAuth2 grant types, allowing you to choose the appropriate authentication flow for your use case:

### Authorization Code Grant

The most secure OAuth2 flow, recommended for server-side applications. Supports PKCE for enhanced security.

**Use Case:** Web applications with a backend server, mobile applications

**Endpoint:** `POST /oauth/token`

```crystal
# Request parameters
{
  "grant_type": "authorization_code",
  "code": "AUTH_CODE",
  "redirect_uri": "https://your-app.com/callback",
  "client_id": "CLIENT_ID",
  "client_secret": "CLIENT_SECRET",
  "code_verifier": "CODE_VERIFIER"  # Optional, for PKCE
}
```

### Client Credentials Grant

Used for server-to-server authentication where the client acts on its own behalf.

**Use Case:** Microservices, background jobs, API integrations

**Endpoint:** `POST /oauth/token`

```crystal
# Request parameters
{
  "grant_type": "client_credentials",
  "client_id": "CLIENT_ID",
  "client_secret": "CLIENT_SECRET",
  "scope": "read write"  # Optional
}
```

### Resource Owner Password Credentials Grant

Allows exchanging username and password directly for tokens. Only use for highly trusted applications.

**Use Case:** First-party applications, legacy system migrations

**Endpoint:** `POST /oauth/token`

```crystal
# Request parameters
{
  "grant_type": "password",
  "username": "USER_NAME",
  "password": "PASSWORD",
  "client_id": "CLIENT_ID",
  "client_secret": "CLIENT_SECRET",
  "scope": "read write"  # Optional
}
```

### Implicit Grant

Returns tokens directly from the authorization endpoint without an intermediate code exchange.

**Use Case:** Single-page applications (deprecated in favor of Authorization Code with PKCE)

**Endpoint:** `GET /oauth/authorize`

### Refresh Token Grant

Allows obtaining a new access token without requiring user interaction.

**Use Case:** Maintaining user sessions, token renewal

**Endpoint:** `POST /oauth/token`

```crystal
# Request parameters
{
  "grant_type": "refresh_token",
  "refresh_token": "REFRESH_TOKEN",
  "client_id": "CLIENT_ID",
  "client_secret": "CLIENT_SECRET",
  "scope": "read" // optional; may only narrow the scope of the original grant
}
```

A refresh token is **single use**. The answer carries a new refresh token (same family) and the old one stops working.
Presenting an already used refresh token revokes the whole family, so a leaked token is detected the first time
either party uses it: the client must sign in again. A refresh token must be a `refresh_token`-typed token issued to
the authenticating client, unexpired and not revoked; the access token it yields keeps the original scope, and the
client must still be allowed that scope (`invalid_scope` otherwise, the token is not consumed). Rotation cannot renew a
sign-in for ever: the family ends `refresh_absolute_ttl` (30 days) after the sign-in (`fexp` claim, which no token
outlives), then the user signs in again. Revoking a refresh token revokes its whole family. Refresh tokens are not
access tokens: `Authly.valid?`, introspection and the bearer handler refuse them.

**Upgrading:** refresh tokens issued by earlier versions (without `cid`, `fid` and `scope`) are refused: users sign in
again. A custom `Authly::TokenGenerator` must override `generate_refresh_token(client_id, jti, sub, scope, family)`
and put `cid`, `scope`, `fid` and `token_type: "refresh_token"` in the token, otherwise its refresh tokens cannot be
redeemed. A custom `TokenStore` needs an atomic `consume` (see "Custom Token Store"); the family is revoked through
`revoke("refresh-family:<fid>")`; override `revoke(token_id, ttl)` too to expire that key after `refresh_ttl`
(the default ignores the TTL). A custom generator should also override the six-argument
`generate_refresh_token(..., family, family_expires_at)` and emit `fexp`; without it the absolute lifetime is not enforced.

### Device Authorization Grant

Enables authentication on devices with limited input capabilities.

**Use Case:** Smart TVs, IoT devices, CLI tools

**Endpoints:**

- `POST /oauth/device/authorize` - Request device code
- `POST /oauth/token` - Exchange device code for tokens

## Authentication Endpoints

Authly provides standard OAuth2 endpoints for authentication flows:

### Pushed Authorization Request Endpoint

**Path:** `POST /oauth/par`

Allows clients to push authorization parameters directly to the authorization server, receiving a short-lived `request_uri` for use in the authorization flow (RFC 9126).

**Request:**

```http
POST /oauth/par HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

response_type=code&
redirect_uri=https://client.example.com/callback&
scope=openid profile&
state=xyz&
code_challenge=CHALLENGE&
code_challenge_method=S256
```

**Response:**

```json
{
  "request_uri": "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY",
  "expires_in": 90
}
```

See [Pushed Authorization Requests](#pushed-authorization-requests-par) for detailed information.

### Authorization Endpoint

**Path:** `GET /oauth/authorize` (consent page) and `POST /oauth/authorize` (the owner's decision)

Initiates the authorization flow for grant types requiring user interaction.

Authly does not own the login: the host application tells it who is signed in.

```crystal
Authly.configure do |config|
  # Returns the subject id of the signed-in resource owner, or nil. It is the ONLY source of the
  # subject of a code or token: `user_id` and `consent` request parameters are ignored.
  config.authenticate_user = ->(context : HTTP::Server::Context) { MySession.user_id(context) }

  # Optional: where to send a visitor who is not signed in (otherwise 401 `login_required`).
  config.login_url = ->(context : HTTP::Server::Context) { "/login?return_to=#{URI.encode_www_form(context.request.resource)}" }

  config.consent_ttl = 10.minutes # how long a consent form stays valid
end
```

While `authenticate_user` is unset the authorization endpoint and the device page refuse every request
(500, nothing is issued). The request is validated first (client, exact `redirect_uri` match, response type,
grant type, requested scope against the client's scopes), then the signed-in owner gets a consent page whose
form carries a signed, single-use token binding client, redirect URI, scope, state and the owner. Only a POST
with that token, from the same signed-in owner, issues the code or token. The pages are served with
`Content-Security-Policy`, `X-Frame-Options: DENY`, `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

**Running more than one node.** Consent and device forms are signed with a key derived from `config.secret_key`, whose
default is random per process: every node must be configured with the same `secret_key`, and the nonces live in
`config.state_store`, which must be shared too (the in-memory default is per process). A custom `StateStore` must make
`consume(state) : Bool` atomic (it answers `true` to exactly one caller, e.g. Redis `DEL` returning 1); the handlers use
only `consume`, never `valid?` followed by `consume`.

**Security notes.** Authorization codes without PKCE are accepted by default and `plain` is a valid method. Set
`config.enforce_pkce = true` and `config.enforce_pkce_s256 = true` for every deployment that has public clients (and
preferably all of them). The scope of an authorization request is required and must be within the client's scopes.

**Parameters:**

- `response_type` - Type of response (`code`, `token`)
- `client_id` - Client identifier
- `redirect_uri` - Callback URL
- `scope` - Requested permissions (optional)
- `state` - CSRF protection token (recommended)
- `code_challenge` - PKCE challenge (optional)
- `code_challenge_method` - PKCE method (`S256` or `plain`)

### Token Endpoint

**Path:** `POST /oauth/token`

Exchanges authorization grants for access tokens.

**Parameters:** Vary by grant type (see [OAuth2 Grant Types](#oauth2-grant-types))

### Introspection Endpoint

**Path:** `POST /oauth/introspect`

Validates and retrieves metadata about a token.

```crystal
# Request
{
  "token": "ACCESS_TOKEN",
  "token_type_hint": "access_token"  # Optional
}

# Response
{
  "active": true,
  "client_id": "CLIENT_ID",
  "username": "USER_NAME",
  "exp": 1640000000,
  "iat": 1639999000,
  "scope": "read write"
}
```

### Revocation Endpoint

**Path:** `POST /oauth/revoke`

Invalidates an access or refresh token.

```crystal
# Request
{
  "token": "TOKEN_TO_REVOKE",
  "token_type_hint": "access_token"  # Optional
}
```

### Device Authorization Endpoints

**Request Device Code:** `POST /oauth/device/authorize`

```crystal
# Response
{
  "device_code": "DEVICE_CODE",
  "user_code": "USER_CODE",
  "verification_uri": "https://your-app.com/device",
  "expires_in": 300,
  "interval": 5
}
```

**Verify Device Code:** `GET /oauth/device/verify`

User visits this endpoint to enter the user code and authorize the device.

The page needs `Authly.config.authenticate_user`. Every lookup of a user code is counted per signed-in owner and per source (approving takes two: the page and the
form) and, past `device_attempt_limit` (10) of them within `device_attempt_window` (15 minutes), the page answers `429`
with `Retry-After` until the window passes. A code is decided once: approving an approved or denied code, or denying an
approved one, is refused. When the owner denies, the device is answered `access_denied` (RFC 8628 3.5) until the code expires. A device that polls the token endpoint faster than `interval` is answered
`slow_down` and its interval grows by 5 seconds. An approved device code yields one token, about the owner who approved it.

```crystal
Authly.configure do |config|
  config.device_attempt_limit = 10
  config.device_attempt_window = 15.minutes
  # Behind a reverse proxy the socket address is the proxy: return the client address it vouches for
  config.attempt_source = ->(context : HTTP::Server::Context) { context.request.headers["X-Real-IP"]? }
  # With several nodes, count in a shared store: implement Authly::AttemptLimiter (exceeded?, increment) over Redis
  # config.attempt_limiter = RedisAttemptLimiter.new       # the device page
  # config.registration_limiter = RedisAttemptLimiter.new  # registration has its own, so one cannot fill the other
end
```

`X-Real-IP` in the example is a request header: a client can send any value, so an attacker rotates it to get a fresh
counter every time **unless your reverse proxy overwrites it** (`proxy_set_header X-Real-IP $remote_addr;` in nginx,
rather than passing the client's value on) and the app is reachable only through that proxy. Without such a proxy keep
the default (the socket address) or return nil to count by account only.

**Shared addresses:** the source is one key. Everything behind one proxy address (when `attempt_source` returns the
proxy's address) counts as one source, and so do all requests when it returns nil (they share the key `unknown`): one
client that fails often enough locks out all the others behind that address for the whole window. Return an address your
proxy vouches for, per client.

**Boundaries:** at the device page the first `device_attempt_limit` lookups of an owner (or of a source) in a window are
answered normally and the next one is `429`. At registration the first `registration_rate_limit` failed authentications of
a source are `401`, the next one `429`, and once that many failures are counted even a request with the right token is `429`.

**Shared limiters:** the handlers count with `increment(key, window) : Int32`, which has to count and answer in one atomic
step, otherwise parallel requests all pass the check before any is counted. For Redis that is `INCR key`, then
`EXPIRE key window` when the answer is `1` (or one Lua script); `exceeded?(key, limit)` is a plain read of the same
counter and `record` is `increment` whose answer is ignored. `InMemoryAttemptLimiter` keeps at most 10,000 keys: when
full it drops expired keys first and, if all are live, counts no new key and answers a count no limit reaches, so
the handler refuses (fail closed) instead of forgetting a live counter. A custom limiter written for 1.3.1 must add `increment`.

**Upgrading:** a custom `DeviceCodeStore` must persist the new `DeviceCodeData#last_polled_at` (it is part of the
record, and `JSON::Serializable` stores it by default); without it `slow_down` never triggers.

### UserInfo Endpoint

**Path:** `GET /oauth/userinfo`

Returns user claims based on the granted scopes in the access token.

**Request:**

```http
GET /oauth/userinfo HTTP/1.1
Authorization: Bearer ACCESS_TOKEN
```

**Response:**

```json
{
  "sub": "user_id_123",
  "name": "John Doe",
  "email": "john@example.com",
  "email_verified": true,
  "picture": "https://example.com/avatar.jpg"
}
```

**Supported Scopes:**

- `openid`: Returns `sub` (subject/user ID)
- `profile`: Returns profile information (name, picture, etc.)
- `email`: Returns email and email_verified
- `address`: Returns address information
- `phone`: Returns phone number information

### OpenID Connect Discovery Endpoint

**Path:** `GET /.well-known/openid-configuration`

Returns OpenID Connect discovery metadata for automatic client configuration.

**Response:**

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "userinfo_endpoint": "https://auth.example.com/oauth/userinfo",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "registration_endpoint": "https://auth.example.com/oauth/register",
  "scopes_supported": ["openid", "profile", "email", "address", "phone"],
  "response_types_supported": ["code", "token", "id_token"],
  "grant_types_supported": ["authorization_code", "client_credentials", ...],
  "code_challenge_methods_supported": ["S256", "plain"]
}
```

### Dynamic Client Registration Endpoint

**Path:** `POST /oauth/register`

Allows clients to dynamically register with the authorization server (RFC 7591).

**Configuration Required:**

```crystal
Authly.configure do |config|
  config.allow_dynamic_registration = true
  config.client_store = CustomClientStore.new

  # Registration is never anonymous. Give callers an initial access token (RFC 7591), a hook, or both;
  # with neither the endpoint answers 500 and registers nothing.
  config.registration_access_token = ENV["REGISTRATION_ACCESS_TOKEN"]            # Authorization: Bearer <token>
  config.authenticate_registration = ->(context : HTTP::Server::Context) { admin?(context) } # Bool

  # What a client may ask for (the defaults are shown); anything else is `invalid_client_metadata`
  config.registration_grant_types = ["authorization_code", "refresh_token"]
  config.registration_response_types = ["code"]
  config.registration_scopes = ["read"] # none by default: a request with a `scope` is refused

  config.registration_max_body = 16 * 1024                 # bytes, else 413
  config.registration_rate_limit = 10                       # failed authentications per source ...
  config.registration_rate_window = 1.hour                  # ... per window, else 429 (requests with the right credentials are not counted)
end
```

Only failed authentications count against a source, since they are what guesses the initial access token; a source
that used up its failures is refused even with the right token until the window passes, so the limit caps the guesses.
The source is `Authly.config.attempt_source`: behind a proxy it is only as trustworthy as that hook (see the note on
`X-Real-IP` under the device flow).

`redirect_uris` (1 to 10) must be exact URIs of one of three kinds: `https`, `http` on a loopback host (`localhost`,
`127.0.0.1`, `[::1]`, RFC 8252), or a private-use scheme named after a domain (`com.example.app:/callback`). A fragment,
user info, wildcard (`*`), blank or control character is refused, so a registered URI can only match itself (the
authorization endpoint compares redirect URIs exactly). `client_uri`, `logo_uri`, `tos_uri`, `policy_uri` and `jwks_uri` must be `https`.
Secrets are 256 random bits (`Random::Secure`).

**Upgrading:** the endpoint used to accept anyone, and `password`, `implicit`, any scope and any `scheme://host` URI.
Set `registration_access_token` or `authenticate_registration`, and widen the allow-lists your clients need.
Registered clients are stored as given to `ClientStore`; Authly's own `Clients` list does not read that store, and the
secret is stored as issued (a store that must not hold it in the clear can hash it before saving).

**Request:**

```json
{
  "redirect_uris": ["https://client.example.com/callback"],
  "client_name": "My Application",
  "client_uri": "https://client.example.com",
  "logo_uri": "https://client.example.com/logo.png",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "openid profile email",
  "contacts": ["admin@client.example.com"]
}
```

**Response:**

```json
{
  "client_id": "client_abcdef123456",
  "client_secret": "secret_xyz789",
  "client_id_issued_at": 1640000000,
  "client_secret_expires_at": 0,
  "redirect_uris": ["https://client.example.com/callback"],
  "client_name": "My Application",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic"
}
```

**Public Clients:**

For public clients (e.g., SPAs, mobile apps), set `token_endpoint_auth_method` to `"none"`:

```json
{
  "redirect_uris": ["https://spa.example.com/callback"],
  "token_endpoint_auth_method": "none"
}
```

Public clients receive a `client_id` but no `client_secret`.

## Advanced Security Features

### Enhanced PKCE with S256 Enforcement

PKCE (Proof Key for Code Exchange) is a security extension for OAuth2 that prevents authorization code interception attacks. Authly now supports enforcing PKCE and mandating the S256 method.

**Configuration:**

```crystal
Authly.configure do |config|
  # Require PKCE for all authorization code flows
  config.enforce_pkce = true

  # Enforce S256 method, reject plain method
  config.enforce_pkce_s256 = true
end
```

**Usage:**

When PKCE is enforced, all authorization requests must include:

- `code_challenge`: The code challenge derived from the code verifier
- `code_challenge_method`: Must be `S256` when enforcement is enabled

**Example Authorization Request:**

```http
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=REDIRECT_URI&
  code_challenge=CHALLENGE&
  code_challenge_method=S256&
  state=STATE
```

**Code Verifier Generation:**

```crystal
# Generate a cryptographically random code verifier
verifier = Random::Secure.hex(32)

# Calculate the S256 challenge
challenge = Digest::SHA256.base64digest(verifier)
```

**Token Exchange:**

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE&
client_id=CLIENT_ID&
redirect_uri=REDIRECT_URI&
code_verifier=VERIFIER
```

### Pushed Authorization Requests (PAR)

Pushed Authorization Requests (RFC 9126) is a security enhancement that moves authorization parameters from the front-channel (browser) to a back-channel (direct server-to-server) request. This prevents parameter tampering, reduces URL length limitations, and provides better security for sensitive authorization data.

**Configuration:**

```crystal
Authly.configure do |config|
  # Enable PAR endpoint (always available)
  config.par_ttl = 90.seconds  # Request URI expiration (default: 90 seconds)

  # Optionally require PAR for all authorization requests
  config.require_par = true

  # Optional: Custom PAR store implementation
  config.par_store = CustomPARStore.new
end
```

**How It Works:**

PAR operates in two steps:

**Step 1: Push Authorization Parameters (Back-channel)**

The client sends authorization parameters directly to the authorization server:

```http
POST /oauth/par HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

response_type=code&
redirect_uri=https://client.example.com/callback&
scope=openid profile email&
state=xyz&
code_challenge=CHALLENGE&
code_challenge_method=S256
```

**Response:**

```json
{
  "request_uri": "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY",
  "expires_in": 90
}
```

**Step 2: Authorization Request (Front-channel)**

The client redirects the user with only the `request_uri`:

```http
GET /oauth/authorize?
  client_id=CLIENT_ID&
  request_uri=urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY
```

**Benefits:**

- **Enhanced Security**: Parameters aren't exposed in browser URLs or server logs
- **Prevents Tampering**: Authorization parameters can't be modified by attackers
- **Large Requests**: Bypasses URL length limitations for complex authorization requests
- **Server-Side Validation**: Parameters validated before user interaction
- **Replay Protection**: Request URIs are single-use and time-limited
- **FAPI Compliant**: Required for Financial-grade API security profiles

**Client Authentication:**

PAR requires client authentication using one of:

- `client_secret_basic`: HTTP Basic authentication (recommended)
- `client_secret_post`: Client credentials in request body

**Security Features:**

- Request URIs expire after 90 seconds (configurable)
- Single-use request URIs (consumed after authorization)
- Client ID validation to prevent unauthorized use
- Automatic cleanup of expired request URIs

### Certificate-Bound Access Tokens (mTLS)

Certificate-bound tokens (RFC 8705) bind access tokens to client certificates, preventing token theft and replay attacks. This feature requires mTLS (mutual TLS) configuration at the HTTP server level.

**Configuration:**

```crystal
Authly.configure do |config|
  # Enable certificate-bound tokens
  config.require_certificate_bound_tokens = true

  # Optional: Specify trusted CA certificates for validation
  config.trusted_ca_certificates = [
    File.read("path/to/ca1.pem"),
    File.read("path/to/ca2.pem")
  ]
end
```

**How It Works:**

1. Client presents a certificate during the TLS handshake
2. Authly calculates the SHA-256 thumbprint of the certificate
3. The thumbprint is embedded in the access token's `cnf` (confirmation) claim
4. When using the token, the client must present the same certificate
5. Authly validates that the certificate matches the bound token

**Token Structure (JWT):**

```json
{
  "sub": "user_id",
  "iss": "https://auth.example.com",
  "exp": 1640000000,
  "cnf": {
    "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"
  }
}
```

**Server Configuration:**

For mTLS to work, your HTTP server must be configured to request client certificates. With Crystal's HTTP::Server and a reverse proxy like nginx:

```nginx
server {
    listen 443 ssl;
    ssl_client_certificate /path/to/ca.pem;
    ssl_verify_client optional;
    ssl_verify_depth 2;

    location / {
        proxy_pass http://authly_backend;
        proxy_set_header X-Client-Certificate $ssl_client_cert;
    }
}
```

**Benefits:**

- Prevents token theft - stolen tokens cannot be used without the certificate
- Suitable for high-security environments (banking, healthcare, government)
- Compliant with FAPI (Financial-grade API) security profile

### JWT Secured Authorization Response Mode (JARM)

JARM (RFC 9101) protects authorization responses by encoding them in signed and optionally encrypted JWTs. This prevents response tampering, injection attacks, and ensures the integrity and authenticity of authorization responses.

**Configuration:**

```crystal
Authly.configure do |config|
  # JARM signing configuration
  config.jarm_signing_key = ENV["JARM_SIGNING_KEY"]
  config.jarm_signing_alg = JWT::Algorithm::RS256

  # Optional: JARM encryption configuration
  config.jarm_encryption_key = ENV["JARM_ENCRYPTION_KEY"]
  config.jarm_encryption_alg = "RSA-OAEP"
  config.jarm_encryption_enc = "A256GCM"

  # Optional: Default JARM response mode
  config.default_jarm_response_mode = "query.jwt"

  # JARM JWT lifetime (default: 10 minutes)
  config.jarm_lifetime = 10.minutes
end
```

**How It Works:**

When JARM is enabled, instead of returning authorization parameters in the query string or fragment:

```
https://client.example.com/callback?code=AUTH_CODE&state=xyz
```

The authorization server returns a signed JWT containing the response:

```
https://client.example.com/callback?response=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

The JWT payload contains:

```json
{
  "iss": "https://auth.example.com",
  "aud": "client_id",
  "exp": 1640000600,
  "code": "AUTH_CODE",
  "state": "xyz"
}
```

**Response Modes:**

JARM supports multiple response modes:

1. **query.jwt** - JWT in query parameter `response`

   ```
   GET /callback?response=<JWT>
   ```

2. **fragment.jwt** - JWT in fragment parameter `response`

   ```
   GET /callback#response=<JWT>
   ```

3. **form_post.jwt** - Auto-submitting HTML form with JWT

   ```html
   <form method="post" action="callback_url">
     <input type="hidden" name="response" value="<JWT>" />
   </form>
   ```

4. **jwt** - Direct JWT response (for JAR flows)

   ```
   HTTP/1.1 200 OK
   Content-Type: application/jwt

   <JWT>
   ```

**Per-Client Configuration:**

Clients can request JARM during dynamic registration:

```json
{
  "redirect_uris": ["https://client.example.com/callback"],
  "authorization_signed_response_alg": "RS256",
  "authorization_encrypted_response_alg": "RSA-OAEP",
  "authorization_encrypted_response_enc": "A256GCM"
}
```

Or configure it statically:

```crystal
client = Authly::Client.new(
  name: "Secure Client",
  secret: "client_secret",
  redirect_uri: "https://client.example.com/callback",
  id: "client_123",
  jarm_signing_alg: "RS256",
  jarm_encryption_alg: "RSA-OAEP",
  jarm_encryption_enc: "A256GCM"
)
```

**Usage Example:**

Client requests authorization with JARM:

```http
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=REDIRECT_URI&
  response_mode=query.jwt&
  state=STATE
```

Authorization server redirects with JARM response:

```http
HTTP/1.1 302 Found
Location: https://client.example.com/callback?response=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

Client decodes and validates the JWT:

```crystal
# Extract JWT from response parameter
jwt = params["response"]

# Verify signature and decode
payload, header = JWT.decode(jwt, server_public_key, JWT::Algorithm::RS256,
  iss: "https://auth.example.com",
  aud: client_id
)

# Extract authorization code
authorization_code = payload["code"]
state = payload["state"]
```

**Supported Algorithms:**

**Signing Algorithms (JWS):**

- RS256, RS384, RS512 (RSA with SHA)
- ES256, ES384, ES512 (ECDSA with SHA)
- HS256, HS384, HS512 (HMAC with SHA)
- PS256, PS384, PS512 (RSA PSS with SHA)

**Encryption Algorithms (JWE - Key Encryption):**

- RSA-OAEP, RSA-OAEP-256
- ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW

**Encryption Encodings (JWE - Content Encryption):**

- A128GCM, A192GCM, A256GCM
- A128CBC-HS256, A192CBC-HS384, A256CBC-HS512

**Benefits:**

- **Response Integrity**: Prevents tampering with authorization responses
- **Response Authentication**: Verifies the authorization server issued the response
- **Confidentiality**: Optional encryption protects sensitive response data
- **Injection Prevention**: Prevents authorization response injection attacks
- **FAPI Compliance**: Required for Financial-grade API Advanced security profile

**Security Considerations:**

- JARM JWTs should have short lifetimes (default: 10 minutes)
- Clients must validate the `iss` (issuer) and `aud` (audience) claims
- Clients must verify JWT signatures using the authorization server's public key
- Use RS256 or ES256 for production deployments (asymmetric algorithms)
- Enable encryption for highly sensitive authorization responses

## Customization

Authly provides extension points for integrating with your application's authentication logic:

### Custom Authorizable Client

Implement the `AuthorizableClient` module to define client authentication and validation:

```crystal
class CustomAuthorizableClient
  include Authly::AuthorizableClient

  def valid_redirect?(redirect_uri : String) : Bool
    # Validate redirect URI against allowed URLs
    # This should query your database or configuration
    allowed_uris = [
      "https://your-app.com/callback",
      "https://your-app.com/oauth/callback"
    ]
    allowed_uris.includes?(redirect_uri)
  end

  def authorized?(client_id : String, client_secret : String) : Bool
    # Verify client credentials
    # This should query your database or authentication service
    client = Client.find_by_id(client_id)
    client && client.secret == client_secret && client.active?
  end
end
```

### Custom Authorizable Owner

Implement the `AuthorizableOwner` module to define resource owner authentication:

```crystal
class CustomAuthorizableOwner
  include Authly::AuthorizableOwner

  def authorized?(username : String, password : String) : Bool
    # Verify user credentials
    # This should use your authentication system (bcrypt, argon2, etc.)
    user = User.find_by_username(username)
    user && user.verify_password(password) && user.active?
  end

  def id_token(user_data : Hash(String, String)) : String
    # Generate an OpenID Connect ID Token
    # Include standard claims like sub, name, email, etc.
    user_id = user_data["user_id"]
    user = User.find(user_id)

    JWT.encode({
      "sub" => user.id,
      "name" => user.full_name,
      "email" => user.email,
      "email_verified" => user.email_verified?,
      "iat" => Time.utc.to_unix,
      "exp" => (Time.utc + 1.hour).to_unix
    }, Authly.configuration.secret_key, Authly.configuration.algorithm)
  end
end
```

### Custom Token Store

For production deployments, implement a persistent token store using your preferred database:

```crystal
class CustomTokenStore
  include Authly::TokenStore

  def store(token : String, data : Hash(String, String))
    # Store token in database with expiration
    Token.create(
      token: token,
      data: data.to_json,
      expires_at: Time.utc + data["ttl"].to_i.seconds
    )
  end

  def fetch(token : String) : Hash(String, String)?
    # Fetch non-expired token from database
    token_record = Token.find_by_token(token)
    return nil unless token_record && !token_record.expired?

    JSON.parse(token_record.data).as(Hash(String, String))
  rescue
    nil
  end

  def revoke(token : String)
    # Mark token as revoked
    Token.where(token: token).update_all(revoked: true)
  end

  def revoked?(token : String) : Bool
    # Check if token has been revoked
    token_record = Token.find_by_token(token)
    token_record.nil? ? false : token_record.revoked?
  end

  def valid?(token : String) : Bool
    # Verify token is not revoked and not expired
    token_record = Token.find_by_token(token)
    return false unless token_record

    !token_record.revoked? && !token_record.expired?
  end
end
```

**Benefits of Custom Token Store:**

- Persistence across server restarts
- Scalability for distributed systems
- Token audit trail and analytics
- Advanced token management features

## Token Strategies

Authly supports two token strategies:

### JWT Tokens (Recommended)

**Advantages:**

- Self-contained and stateless
- No database lookup required for validation
- Contains user information and metadata
- Industry-standard format

**Configuration:**

```crystal
Authly.configure do |config|
  config.token_strategy = :jwt
  config.algorithm = JWT::Algorithm::HS256  # or RS256, ES256, etc.
  config.secret_key = ENV["JWT_SECRET_KEY"]
end
```

**Supported Algorithms:**

- HS256, HS384, HS512 (HMAC with SHA)
- RS256, RS384, RS512 (RSA with SHA)
- ES256, ES384, ES512 (ECDSA with SHA)

### Opaque Tokens

**Advantages:**

- Revocable without database lookups
- No sensitive data exposure
- Smaller token size

**Configuration:**

```crystal
Authly.configure do |config|
  config.token_strategy = :opaque
  config.token_store = CustomTokenStore.new  # Required for opaque tokens
end
```

## Protecting Your API

`Authly::Handler` is the authorization server. The handlers below are for the **resource server**: the
routes that accept access tokens. They are plain `HTTP::Handler`s with no web framework behind them, so
they go into any handler chain.

### Bearer Handler

`Authly::Handler::Bearer` reads `Authorization: Bearer <token>`, verifies it with Authly's own
configuration and hands the verified claims to the handlers after it:

```crystal
require "authly"

server = HTTP::Server.new([
  Authly::Handler::Bearer.new(realm: "api", except_exact: ["/health"]),
  MyApp.new,
])
```

`Bearer` protects **every** request except the paths in `except` (see below). Downstream, the claims are
`context.authly_claims` (an `Authly::Claims`, `nil` where the handler did not apply) or
`context.authly_claims!`, which raises `Authly::MissingClaims` instead of returning nil. They are an instance variable of that request's own `HTTP::Server::Context`, so concurrent
requests never see each other's claims and nothing global has to be cleaned up:

```crystal
class MyApp
  include HTTP::Handler

  def call(context)
    claims = context.authly_claims!
    claims.subject            # "sub"
    claims.client_id          # "cid"
    claims.scopes             # ["read:users", "write:users"]
    claims.scope?("read:users")
    claims["exp"].as_i64      # any other claim, as JSON::Any
  end
end
```

What is verified: the signature with the configured `algorithm` (the token's own `alg` header is never
trusted, so `alg: none` and key-confusion tokens fail), `exp` (required), `nbf`, the issuer, and
revocation. Only **access tokens** pass: they carry `token_type: "access_token"`, and a refresh token (same
key, other type) is refused. Both `:jwt` and `:opaque` token strategies work. The token is decoded once per
request. Tokens issued before `token_type` existed (up to `access_ttl` old after an upgrade) are accepted
only with `StrategyTokenVerifier.new(legacy_tokens: true)`, for the length of that rollout.

**Set an audience.** Access tokens carry `aud` (`config.access_token_audience`, `base_url` by default). A
resource server that does not check it accepts a token minted for *any* API that shares the key (a confused
deputy). Give each API its own audience and check it:

```crystal
# on the authorization server
config.access_token_audience = "https://api.example.com"

# on the resource server
verifier = Authly::StrategyTokenVerifier.new(audience: "https://api.example.com")
Authly::Handler::Bearer.new(verifier, realm: "api", except_exact: ["/health"])
```

Without `audience:` any `aud` is accepted. Authly issues one audience per server, not per request
(no RFC 8707 resource indicators), so use one authorization server per audience if APIs must be isolated.

Anything else (remote introspection, another key source) is an `Authly::TokenVerifier`: implement
`verify(token : String) : Authly::Claims?` and pass it as the first argument.

Failures follow RFC 6750 and never echo the token or log it:

| Request                                    | Status | `WWW-Authenticate`                               |
| ------------------------------------------ | ------ | ------------------------------------------------ |
| No credentials (or another scheme)         | 401    | `Bearer realm="api"`                             |
| Malformed header, two headers, empty token | 400    | `Bearer realm="api", error="invalid_request"`    |
| Bad, expired, revoked, wrong-key token     | 401    | `Bearer realm="api", error="invalid_token"`      |
| Valid token without the required scope     | 403    | `... error="insufficient_scope", scope="a b"`    |
| Token store unreachable (Redis down)       | 503    | none; `Retry-After: 1`                           |

A store outage is a 503, not a 401. A `TokenStore` signals it by raising `Authly::StoreUnavailable` (an `IO::Error` counts too);
it raises `Authly::Error` from `fetch` for an unknown token, and any other exception is read as "not a valid token" (401), so a
store that raises `KeyError` for an unknown token cannot be used to make the server answer 503. A 401 would send every client off to re-authenticate: a 401 would send every client off to re-authenticate. It still fails
closed (nobody gets in).

The scheme is case-insensitive (`bearer`, `BEARER`); a tab is not a separator. The token is read from the
header only. Set `allow_query_token: true` to also accept `?access_token=` (one value only; a header as well
is refused). RFC 6750 discourages it: URLs end up in access logs, referrers and browser history, so
make sure your logs do not record query strings. Such responses get `Cache-Control: private` and
`Referrer-Policy: no-referrer`.

**Which paths.** Everything is protected except what you list, so a route added later is protected by
default. `except_exact: ["/health"]` exempts just that path (`/health` and `/health/`, not `/health/details`):
use it for health checks. `except: ["/oauth"]` is a **segment-prefix** match, case-sensitive: it exempts
`/oauth` **and everything below it**, not `/oauthx`. `prefixes: ["/api"]` is the opposite, an
**allowlist: every path you do not list is open**. A forgotten route, a new top-level path or a router that
matches differently is then unprotected, so prefer the other two. Paths are compared after percent-decoding
(once, like a router), collapsing `//` and resolving `.`/`..`, so `/%61pi/x`, `//api/x` and `/x/../api/x` are
`/api/x`. A path that still has a `%` after decoding (double encoding, `%zz`) or a NUL byte is not
understood, and is protected. `prefixes` ignores case (`/API/x` is protected), `except`/`except_exact` do not
(`/HEALTH` is not exempted by `/health`). A trailing slash does not matter, `prefixes: []` is refused, and an
entry with encoded characters is refused.

**CORS.** Put the CORS handler **before** `Bearer`, or a browser cannot read the 401. A preflight
(`OPTIONS` with `Access-Control-Request-Method`) carries no credentials: either let the CORS handler
answer it, or give `Bearer` **and `RequireScope`** `pass_preflight: true` to hand it to the next handler. Off
by default. A preflight is recognised by headers anyone can send, so what answers `OPTIONS` behind this flag is
**public** and must have no side effects.

### Requiring Scopes

`Authly::Handler::RequireScope` goes after `Bearer`. `all` needs every scope listed, `any` at least one:

```crystal
HTTP::Server.new([
  Authly::Handler::Bearer.new(except_exact: ["/health"]),
  Authly::Handler::RequireScope.all("read:users", prefixes: ["/users"]),
  Authly::Handler::RequireScope.any("admin", "root", prefixes: ["/admin"]),
  MyApp.new,
])
```

`RequireScope.new(all: [...], any: [...])` needs both. It takes `prefixes:`, `except:`, `except_exact:` and `pass_preflight:` like `Bearer` and applies to
every path unless narrowed, so repeat the `except` paths of `Bearer` if it is used without `prefixes`. A request that lacks a scope gets
`403` with `error="insufficient_scope"` and the scopes it needs; a request that no `Bearer` authenticated
gets `401`, it is never let through. Scope names and realms are checked when the handler is built, so a
value cannot inject into the challenge header.

### JWKS and Metadata

`GET /.well-known/jwks.json` serves the key set tokens are verified with, and
`GET /.well-known/oauth-authorization-server` (RFC 8414) serves the same metadata as
`/.well-known/openid-configuration`. Both are routes of `Authly::Handler`; `Authly::JWKS.new.to_json`
builds the document without a server.

A key set only makes sense for **asymmetric** algorithms. Authly signs with HS256 by default, where the
verification key is the signing secret and must never be published, so the set is empty (`{"keys":[]}`).
To publish a key, sign with RS256/RS384/RS512 or ES256/ES384/ES512 and set the public half as a PEM:

```crystal
Authly.configure do |config|
  config.algorithm = JWT::Algorithm::RS256
  config.secret_key = File.read("private.pem")
  config.public_key = File.read("public.pem")
end
```

The key is published with `use`, `alg` and a `kid` (its RFC 7638 thumbprint). Authly does not put `kid`
in the tokens it issues and publishes one key, so rotation (several keys at once) is not supported yet.
The algorithm has to fit the key (RS* an RSA key, ES256/384/512 an EC key on P-256/P-384/P-521). A private key, a key that does not fit, or anything that is not a PEM public key, is refused (the endpoint answers 500 with `Cache-Control: no-store`) instead of
being published; a published set is `public, max-age=300`. EdDSA, PS* and ES256K are not published.

The metadata's `issuer` is `base_url`, while tokens carry `iss` = `config.issuer`. Set both to the same
URL if clients validate the metadata issuer against the token.

A resource server that is a separate process can verify the same tokens by configuring the public key
(`algorithm` and `public_key`) and using `Bearer`; revocation is only seen where the token store is shared.

### Mounting in an Azu App

Authly needs no Azu, and Azu is not a dependency of it. In an [Azu](https://github.com/azutoolkit/azu)
app, `Azu::App#server` takes the handler chain, and every `HTTP::Handler` is routable, so put the
handlers after the app's default ones:

```crystal
require "azu"
require "authly"

app = Azu::App.default
app.router.get "/users", UsersEndpoint.new

server = app.server([
  *app.default_handlers,
  Authly::Handler.new,
  Authly::Handler::Bearer.new(except_exact: ["/health"], except: ["/oauth"]),
  Authly::Handler::RequireScope.all("read:users", prefixes: ["/users"]),
] of HTTP::Handler)
```

An endpoint reads `context.authly_claims`. **This snippet is unchecked**: Azu is not a dependency of Authly,
so CI does not compile it (it was written against Azu master's `App#server` and `default_handlers`). The
Authly specs run the same handler chain over a real `HTTP::Server`.

## Roadmap

### Completed Features ✅

- [x] OAuth2 Dynamic Client Registration (RFC 7591)
- [x] OpenID Connect UserInfo endpoint
- [x] OpenID Connect Discovery endpoint
- [x] Certificate-bound access tokens (mTLS / RFC 8705)
- [x] Enhanced PKCE implementation with S256 method enforcement
- [x] Pushed Authorization Requests (PAR / RFC 9126)
- [x] JWT Secured Authorization Response Mode (JARM / RFC 9101)

### Planned Enhancements

- [ ] Rate limiting and throttling for authentication endpoints
- [ ] Session management capabilities
- [ ] Additional token storage backends (Redis, Memcached)
- [x] JWKS endpoint and RFC 8414 metadata (asymmetric algorithms only)
- [ ] JWKS key rotation (several published keys)
- [ ] Comprehensive integration examples
- [ ] Admin UI for client and token management
- [ ] Detailed logging and monitoring hooks

See the [open issues](https://github.com/azutoolkit/authly/issues) for a list of proposed features and known issues.

## Contributing

Contributions are what make the open-source community an amazing place to learn, inspire, and create. We welcome contributions of all kinds!

### How to Contribute

1. **Fork the Project** - Create your own fork of the repository
2. **Create a Feature Branch** - `git checkout -b feature/amazing-feature`
3. **Make Your Changes** - Implement your feature or bug fix
4. **Write Tests** - Ensure your changes are covered by tests
5. **Run the Test Suite** - `crystal spec` to verify all tests pass
6. **Run the Linter** - `bin/ameba` to ensure code quality
7. **Commit Your Changes** - `git commit -m 'Add some amazing feature'`
8. **Push to Your Branch** - `git push origin feature/amazing-feature`
9. **Open a Pull Request** - Submit your PR with a clear description

### Code Style

- Follow Crystal's official style guide
- Write clear, descriptive commit messages
- Add documentation for new features
- Include specs for all new functionality

### Reporting Issues

Found a bug or have a feature request? Please open an issue on GitHub with:

- A clear, descriptive title
- Detailed description of the issue or feature
- Steps to reproduce (for bugs)
- Expected vs actual behavior
- Environment details (Crystal version, OS, etc.)

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Contact

**Elias J. Perez**

- GitHub: [@eliasjpr](https://github.com/eliasjpr)
- Project Link: [https://github.com/azutoolkit/authly](https://github.com/azutoolkit/authly)

---

<div align="center">
  Made with ❤️ by the Crystal community
</div>
