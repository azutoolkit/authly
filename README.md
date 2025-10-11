# Authly

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/747eef2e02594d40b63c9f05c6b94cd9)](https://app.codacy.com/manual/eliasjpr/authly?utm_source=github.com&utm_medium=referral&utm_content=eliasjpr/authly&utm_campaign=Badge_Grade_Settings) [![Crystal CI](https://github.com/azutoolkit/authly/actions/workflows/crystal.yml/badge.svg?branch=master)](https://github.com/azutoolkit/authly/actions/workflows/crystal.yml)

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
  "client_secret": "CLIENT_SECRET"
}
```

### Device Authorization Grant

Enables authentication on devices with limited input capabilities.

**Use Case:** Smart TVs, IoT devices, CLI tools

**Endpoints:**

- `POST /oauth/device/authorize` - Request device code
- `POST /oauth/token` - Exchange device code for tokens

## Authentication Endpoints

Authly provides standard OAuth2 endpoints for authentication flows:

### Authorization Endpoint

**Path:** `GET /oauth/authorize`

Initiates the authorization flow for grant types requiring user interaction.

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
end
```

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

## Roadmap

### Completed Features ✅

- [x] OAuth2 Dynamic Client Registration (RFC 7591)
- [x] OpenID Connect UserInfo endpoint
- [x] OpenID Connect Discovery endpoint
- [x] Certificate-bound access tokens (mTLS / RFC 8705)
- [x] Enhanced PKCE implementation with S256 method enforcement

### Planned Enhancements

- [ ] Rate limiting and throttling for authentication endpoints
- [ ] Session management capabilities
- [ ] Additional token storage backends (Redis, Memcached)
- [ ] JWKS (JSON Web Key Set) endpoint for key rotation
- [ ] Comprehensive integration examples
- [ ] Admin UI for client and token management
- [ ] Detailed logging and monitoring hooks
- [ ] Pushed Authorization Requests (PAR / RFC 9126)
- [ ] JWT Secured Authorization Response Mode (JARM)

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
