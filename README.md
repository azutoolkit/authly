# Authly

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/747eef2e02594d40b63c9f05c6b94cd9)](https://app.codacy.com/manual/eliasjpr/authly?utm_source=github.com&utm_medium=referral&utm_content=eliasjpr/authly&utm_campaign=Badge_Grade_Settings)
[![Crystal CI](https://github.com/azutoolkit/authly/actions/workflows/crystal.yml/badge.svg)](https://github.com/azutoolkit/authly/actions/workflows/crystal.yml)

<div align="center">
  <img src="https://raw.githubusercontent.com/azutoolkit/authly/master/authly.png" alt="Authly Logo" />
  <p><strong>A standards-compliant OAuth 2.0, OpenID Connect, and Resource Server security shard for Crystal</strong></p>
</div>

**Authly** is a zero-framework OAuth 2.0 and OpenID Connect library built directly on Crystal's standard `HTTP::Handler`. Mount it as an **Authorization Server** (`Authly::Handler`), protect your API routes as a **Resource Server** (`Authly::Handler::Bearer` and `Authly::Handler::RequireScope`), or run both together in the same process or across microservices.

---

## Key Capabilities

| Area | Supported Standards & Features |
| :--- | :--- |
| **OAuth 2.0 Grants** | Authorization Code (`authorization_code`), Client Credentials (`client_credentials`), Refresh Token (`refresh_token` with rotation & family reuse detection), Device Authorization (`urn:ietf:params:oauth:grant-type:device_code`), Cryptographic Challenge-Response (`challenge_response` / `urn:ietf:params:oauth:grant-type:challenge`), Social Sign-In (`social` / `urn:ietf:params:oauth:grant-type:social`), Password (`password`), Implicit (`implicit`) |
| **Social Sign-In** | Built-in adapters for **Google**, **GitHub**, **Apple**, **Microsoft / Entra ID**, **Discord**, and generic OAuth2/OIDC providers (`GET /oauth/social/:provider`, `GET\|POST /oauth/social/:provider/callback`, and `POST /oauth/token`) |
| **OpenID Connect** | `id_token` issuance (`nonce`, `acr`, `amr`, `auth_time`), `GET /oauth/userinfo`, OIDC Discovery (`/.well-known/openid-configuration`), OAuth 2.0 Authorization Server Metadata (`/.well-known/oauth-authorization-server` — RFC 8414), JWKS (`/.well-known/jwks.json` — RFC 7517) |
| **FAPI & Advanced Security** | PKCE with `S256` enforcement (RFC 7636), Pushed Authorization Requests (`POST /oauth/par` — RFC 9126), JWT Secured Authorization Response Mode (JARM — RFC 9101), Certificate-Bound Access Tokens (`cnf.x5t#S256` mTLS — RFC 8705), Dynamic Client Registration (`POST /oauth/register` — RFC 7591) |
| **Token Lifecycle** | `:jwt` (`HS*`, `RS*`, `ES*`) and `:opaque` token strategies, asymmetric key rotation (`signing_key_id` + `verification_keys`), Token Introspection (`POST /oauth/introspect` — RFC 7662), Token Revocation (`POST /oauth/revoke` — RFC 7009), host-controlled `IssuanceOptions` |
| **Resource Server Protection** | `Authly::Handler::Bearer` (RFC 6750 verification, audience checking, `context.authly_claims!`) and `Authly::Handler::RequireScope` (route-level `all` / `any` scope enforcement) |

---

## Installation

Add `authly` to your `shard.yml`:

```yaml
dependencies:
  authly:
    github: azutoolkit/authly
```

Then run:

```bash
shards install
```

**Requirements:** Crystal `>= 1.22.0`

---

## Quick Start

Create a working OAuth 2.0 Authorization Server and protected Resource API in a single file:

```crystal
require "http/server"
require "json"
require "authly"

Authly.configure do |config|
  config.issuer = "http://localhost:8080"
  config.base_url = "http://localhost:8080"
  config.secret_key = ENV.fetch("AUTHLY_SECRET_KEY", "dev-secret-change-in-production-32b")
  config.algorithm = JWT::Algorithm::HS256
  config.token_strategy = :jwt
end

# Register a client for machine-to-machine authentication
Authly.clients << Authly::Client.new(
  name: "Billing Service",
  secret: "billing-secret-123",
  redirect_uri: "http://localhost:8080/callback",
  id: "billing-service",
  scopes: "invoices:read invoices:write",
  allowed_grant_types: ["client_credentials"]
)

app = HTTP::Handler::HandlerProc.new do |context|
  case context.request.path
  when "/health"
    context.response.content_type = "application/json"
    context.response.print({status: "ok"}.to_json)
  when "/api/invoices"
    claims = context.authly_claims!
    context.response.content_type = "application/json"
    context.response.print({
      client_id: claims.client_id,
      scopes:    claims.scopes,
      invoices:  [{id: "inv_01", amount_cents: 4500}],
    }.to_json)
  else
    context.response.status = HTTP::Status::NOT_FOUND
  end
end

server = HTTP::Server.new([
  Authly::Handler.new,
  Authly::Handler::Bearer.new(
    realm: "api",
    except_exact: ["/health"],
    except: ["/oauth", "/.well-known"]
  ),
  Authly::Handler::RequireScope.all("invoices:read", prefixes: ["/api/invoices"]),
  app,
] of HTTP::Handler)

address = server.bind_tcp("127.0.0.1", 8080)
puts "Listening on http://#{address}"
server.listen
```

Issue a token and call the protected API:

```bash
# 1. Request an access token
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/oauth/token \
  -u "billing-service:billing-secret-123" \
  -d "grant_type=client_credentials&scope=invoices:read" | jq -r .access_token)

# 2. Call the protected endpoint
curl -i http://127.0.0.1:8080/api/invoices \
  -H "Authorization: Bearer $TOKEN"
```

---

## Documentation

Full documentation is available in [`docs/`](docs/README.md):

### [Tutorials](docs/tutorials/README.md)
Step-by-step guides that walk you through building working applications from scratch:
- **[Getting Started: Your First OAuth2 Server & Protected API](docs/tutorials/getting-started.md)** — Launch an OAuth2 server, issue a `client_credentials` token, and protect an endpoint.
- **[Interactive User Sign-In with Authorization Code, PKCE & OIDC](docs/tutorials/authorization-code-pkce.md)** — Connect host user sessions, render consent, verify `S256` PKCE, and fetch UserInfo.
- **[Passwordless Authentication with Challenge-Response](docs/tutorials/challenge-response-auth.md)** — Authenticate clients and users with Ed25519 or HMAC-SHA256 challenge nonces.

### [How-To Guides](docs/how-to/README.md)
Practical recipes for configuring production features:
- **[Implement Custom Clients, Owners & Persistent Redis Stores](docs/how-to/custom-stores-and-models.md)** — Wire `AuthorizableClient`, `AuthorizableOwner`, `TokenStore`, `ChallengeStore`, `StateStore`, and `AttemptLimiter` to SQL and Redis.
- **[Protect Resource APIs & Mount in Azu](docs/how-to/protect-resource-apis.md)** — Configure `Authly::Handler::Bearer`, `Authly::Handler::RequireScope`, audience validation, CORS preflights, and Azu middleware chains.
- **[Enable FAPI & Advanced Security (PKCE, PAR, JARM, mTLS)](docs/how-to/fapi-and-advanced-security.md)** — Enforce `S256` PKCE, Pushed Authorization Requests (`POST /oauth/par`), JARM signed/encrypted responses, and certificate-bound tokens.
- **[Configure Asymmetric Keys, Key Rotation & JWKS](docs/how-to/key-rotation-and-jwks.md)** — Sign with `RS256` / `ES256`, rotate keys without downtime via `verification_keys`, and customize claims with `IssuanceOptions`.
- **[Configure Dynamic Client Registration & Device Authorization](docs/how-to/dynamic-client-registration.md)** — Enable RFC 7591 registration (`POST /oauth/register`) and RFC 8628 smart-TV/CLI device flows (`POST /oauth/device/code` & `/device`).
- **[Configure Social Sign-In](docs/how-to/social-sign-in.md)** — Integrate Google, GitHub, Apple, Microsoft, Discord, and custom OAuth2/OIDC providers via redirect callbacks or `POST /oauth/token`.

### [Reference](docs/reference/README.md)
Complete technical specifications:
- **[`Authly::Configuration` Reference](docs/reference/configuration.md)** — Every setting, TTL, store, security flag, and callback on `Authly.config`.
- **[HTTP Endpoints & Wire Protocol](docs/reference/http-endpoints.md)** — Request parameters, headers, and JSON responses for all endpoints.
- **[Crystal API, Grants & Store Interfaces](docs/reference/grants-and-interfaces.md)** — Signatures for `Authly`, `AuthorizableClient`, `AuthorizableOwner`, `ChallengeVerifier`, `Claims`, and all stores.
- **[Errors & RFC 6750 Challenge Responses](docs/reference/errors.md)** — `Authly::Error` codes, HTTP statuses, and `WWW-Authenticate` error responses.

### [Explanation](docs/explanation/README.md)
Architectural overviews and security design:
- **[Architecture & Design Principles](docs/explanation/architecture.md)** — How Authly separates the Authorization Server, Resource Server, host login session, and stores.
- **[Token Strategies & Refresh Token Lifecycle](docs/explanation/token-strategies-and-lifecycle.md)** — `:jwt` vs. `:opaque` trade-offs, token-type separation, and refresh token rotation with family theft detection.
- **[Security Model & Multi-Node Deployment](docs/explanation/security-model.md)** — Atomic `consume` guarantees, constant-time challenge verification, fail-closed rate limiting, and multi-node checklists.

---

## HTTP Endpoints Overview

`Authly::Handler` mounts the following endpoints out of the box:

| Method(s) | Path | Purpose |
| :--- | :--- | :--- |
| `GET`, `POST` | `/oauth/authorize` | Interactive authorization & user consent (RFC 6749, OIDC, PKCE, PAR, JARM) |
| `POST` | `/oauth/token` | Token issuance & refresh (`authorization_code`, `client_credentials`, `refresh_token`, `password`, `device_code`, `challenge_response`) |
| `POST` | `/oauth/par` | Pushed Authorization Requests (RFC 9126) |
| `POST` | `/oauth/challenge` | Cryptographic Challenge-Response nonce issuance |
| `GET` | `/oauth/social/:provider` | Social Sign-In redirect initiation (PKCE + signed CSRF `state`) |
| `GET`, `POST` | `/oauth/social/:provider/callback` | Social Sign-In provider callback |
| `POST` | `/oauth/device/code` | Device Authorization code issuance (RFC 8628) |
| `GET`, `POST` | `/device` | End-user device code verification page (RFC 8628) |
| `POST` | `/oauth/introspect`, `/introspect` | Token Introspection (RFC 7662) |
| `POST` | `/oauth/revoke`, `/revoke` | Token Revocation (RFC 7009) |
| `GET` | `/oauth/userinfo` | OpenID Connect UserInfo claims |
| `POST` | `/oauth/register` | Dynamic Client Registration (RFC 7591) |
| `GET`, `HEAD` | `/.well-known/openid-configuration` | OpenID Connect Discovery 1.0 metadata |
| `GET`, `HEAD` | `/.well-known/oauth-authorization-server` | OAuth 2.0 Authorization Server Metadata (RFC 8414) |
| `GET`, `HEAD` | `/.well-known/jwks.json` | JSON Web Key Set (RFC 7517) |

---

## Development & Contributing

Contributions are welcome! To work on Authly locally:

```bash
# Install dependencies
shards install

# Run the test suite
crystal spec

# Check formatting
crystal tool format --check src spec

# Run static code analysis
crystal run lib/ameba/src/cli.cr
```

1. Fork the repository (`https://github.com/azutoolkit/authly/fork`)
2. Create your feature branch (`git checkout -b feat/my-feature`)
3. Write specs covering your changes in `spec/`
4. Ensure `crystal spec`, `crystal tool format --check src spec`, and `ameba` pass
5. Open a Pull Request

---

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.

## Contact

**Elias J. Perez** — [@eliasjpr](https://github.com/eliasjpr) · [https://github.com/azutoolkit/authly](https://github.com/azutoolkit/authly)
