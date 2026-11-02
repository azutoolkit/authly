---
description: Complete HTTP wire protocol specification for every endpoint mounted by Authly::Handler.
icon: globe
---

# HTTP Endpoints & Wire Protocol

`Authly::Handler` routes the following OAuth2 and OpenID Connect endpoints. All other paths fall through to the next handler in the `HTTP::Server` chain.

---

## Endpoint Summary

| Method(s) | Path | Handler | Specification |
| :--- | :--- | :--- | :--- |
| `GET`, `POST` | `/oauth/authorize` | `Authly::AuthorizationHandler` | RFC 6749, OIDC Core, RFC 7636 (PKCE), RFC 9101 (JARM) |
| `POST` | `/oauth/token` | `Authly::AccessTokenHandler` / `Authly::RefreshTokenHandler` | RFC 6749, RFC 8628, Challenge-Response |
| `POST` | `/oauth/par` | `Authly::PARHandler` | RFC 9126 (Pushed Authorization Requests) |
| `POST` | `/oauth/challenge` | `Authly::ChallengeHandler` | Challenge-Response Nonce Issuance |
| `POST` | `/oauth/device/code` | `Authly::DeviceAuthorizationHandler` | RFC 8628 Section 3.1 |
| `GET`, `POST` | `/device` | `Authly::DeviceVerificationHandler` | RFC 8628 Section 3.3 |
| `POST` | `/oauth/introspect`, `/introspect` | `Authly::IntrospectHandler` | RFC 7662 (Token Introspection) |
| `POST` | `/oauth/revoke`, `/revoke` | `Authly::RevokeHandler` | RFC 7009 (Token Revocation) |
| `GET` | `/oauth/userinfo` | `Authly::UserInfoHandler` | OIDC Core Section 5.3 |
| `POST` | `/oauth/register` | `Authly::ClientRegistrationHandler` | RFC 7591 (Dynamic Client Registration) |
| `GET`, `HEAD` | `/.well-known/openid-configuration` | `Authly::DiscoveryHandler` | OIDC Discovery 1.0 |
| `GET`, `HEAD` | `/.well-known/oauth-authorization-server` | `Authly::DiscoveryHandler` | RFC 8414 |
| `GET`, `HEAD` | `/.well-known/jwks.json` | `Authly::JWKSHandler` | RFC 7517 (JSON Web Key Set) |

---

## 1. `GET` & `POST /oauth/authorize`

{% tabs %}
{% tab title="GET /oauth/authorize" %}
### Query Parameters
- `response_type` (required unless `request_uri` is used): `"code"` or `"token"`.
- `client_id` (required): Registered client identifier.
- `redirect_uri` (required unless `request_uri` is used): Exact registered callback URI.
- `scope` (required unless `request_uri` is used): Space-delimited scopes.
- `state` (recommended): Opaque CSRF value echoed back on redirect.
- `nonce` (optional): OpenID Connect replay protection value echoed in `id_token`.
- `code_challenge` (optional, or required when `enforce_pkce = true`): PKCE challenge.
- `code_challenge_method` (optional): `"S256"` or `"plain"`.
- `request_uri` (optional, or required when `require_par = true`): PAR URI from `POST /oauth/par`.
- `response_mode` (optional): `"query"`, `"fragment"`, `"form_post"`, `"query.jwt"`, `"fragment.jwt"`, `"form_post.jwt"`, or `"jwt"`.
{% endtab %}

{% tab title="POST /oauth/authorize" %}
### Form Parameters
- `consent_token` (required): Single-use signed token rendered on the consent form.
- `decision` (required): `"approve"` or `"deny"`.
{% endtab %}
{% endtabs %}

---

## 2. `POST /oauth/challenge`

Issues a cryptographically random, single-use challenge bound to `client_id`. Accepts `application/x-www-form-urlencoded`, `application/json`, and optional HTTP Basic client authentication.

### Request Parameters
- `client_id` (required): Registered client identifier.
- `client_secret` (optional): Client secret (verified if provided).
- `username` (optional): Resource owner username.
- `owner_id` (optional): Resource owner ID.
- `key_id` (optional): Cryptographic key identifier.

### Success Response (`200 OK`, `Cache-Control: no-store`)
```json
{
  "challenge_id": "4f8c1d7e2a9b0c3d5e6f7a8b9c0d1e2f",
  "challenge": "a3f19b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a",
  "expires_in": 60
}
```

---

## 3. `POST /oauth/token`

Exchanges an authorization grant for an `AccessToken`.

### Client Authentication
- `client_secret_basic` (`Authorization: Basic base64(client_id:client_secret)`)
- `client_secret_post` (`client_id` and `client_secret` in form body)
- For `challenge_response` / `urn:ietf:params:oauth:grant-type:challenge`: `client_id` alone is accepted when authenticating via asymmetric or HMAC challenge response.

### Parameters by `grant_type`

| `grant_type` | Required Parameters | Optional Parameters |
| :--- | :--- | :--- |
| `authorization_code` | `code`, `redirect_uri`, `client_id`, `client_secret` | `code_verifier` |
| `client_credentials` | `client_id`, `client_secret` | `scope` |
| `password` | `username`, `password`, `client_id`, `client_secret` | `scope` |
| `refresh_token` | `refresh_token`, `client_id`, `client_secret` | `scope` (may only narrow original scope) |
| `urn:ietf:params:oauth:grant-type:device_code` | `device_code`, `client_id`, `client_secret` | — |
| `challenge_response` / `urn:ietf:params:oauth:grant-type:challenge` | `client_id`, `challenge_id`, `response` | `client_secret`, `scope`, `key_id`, `algorithm` |

### Success Response (`200 OK`, `Cache-Control: no-store`)
```json
{
  "sub": "user-123",
  "jti": "9d8e7f6a...",
  "access_token": "eyJ0eXAiOiJKV1Qi...",
  "token_type": "Bearer",
  "scope": "read write",
  "expires_in": 3600,
  "refresh_token": "eyJ0eXAiOiJKV1Qi...",
  "id_token": "eyJ0eXAiOiJKV1Qi..."
}
```

{% hint style="info" %}
`refresh_token` and `id_token` are omitted from the JSON payload when `nil`.
{% endhint %}

---

## 4. `POST /oauth/par`

Requires client authentication (`client_secret_basic` or `client_secret_post`). Accepts authorization request parameters (`response_type`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`, `nonce`) and returns `201 Created`:

```json
{
  "request_uri": "urn:ietf:params:oauth:request_uri:...",
  "expires_in": 90
}
```

---

## 5. `POST /oauth/introspect` & `POST /oauth/revoke`

Both endpoints require client authentication (`client_secret_basic` or `client_secret_post`).

{% tabs %}
{% tab title="POST /oauth/introspect" %}
- Form param: `token` (required).
- Returns `200 OK` with `{"active": true, "scope": "...", "cid": "...", "exp": 1700000000, "sub": "..."}` or `{"active": false}`.
{% endtab %}

{% tab title="POST /oauth/revoke" %}
- Form param: `token` (required).
- Revokes the token (and its refresh family if it is a refresh token) only if the token was issued to the authenticating client; always returns `200 OK` per RFC 7009.
{% endtab %}
{% endtabs %}

---

## 6. `GET /oauth/userinfo`

Requires `Authorization: Bearer <access_token>`. Returns claims filtered by the access token's granted scopes (`openid`, `profile`, `email`, `address`, `phone`).

---

## 7. `GET /.well-known/openid-configuration` & `GET /.well-known/jwks.json`

- `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`: Return server metadata including `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `registration_endpoint`, `revocation_endpoint`, `introspection_endpoint`, `device_authorization_endpoint`, `pushed_authorization_request_endpoint`, and `challenge_endpoint`.
- `/.well-known/jwks.json`: Returns `{"keys": [...]}` for asymmetric algorithms (`RS*`, `ES*`), or `{"keys": []}` for symmetric HMAC algorithms.
