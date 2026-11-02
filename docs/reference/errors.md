---
description: Complete catalog of Authly::Error codes, HTTP status mappings, and RFC 6750 WWW-Authenticate headers.
icon: triangle-exclamation
---

# Errors & RFC 6750 Challenge Responses

## 1. `Authly::Error(Code)` (`src/authly/error.cr`)

All OAuth2 protocol errors inherit from `Authly::Error(Code) < Exception`, carrying `#code : Int32` (HTTP status code), `#type : Symbol` (OAuth2 error code), and `#message : String` (`error_description`).

| Factory Method | Error Symbol (`#type`) | HTTP Status (`#code`) | Default `error_description` (`#message`) |
| :--- | :--- | :--- | :--- |
| `Error.invalid_request` | `:invalid_request` | `400` | `"The request is missing a parameter so the server can't proceed with the request"` |
| `Error.invalid_client` | `:invalid_client` | `401` | `"Client authentication failed, such as if the request contains an invalid client ID or secret."` |
| `Error.unauthorized_client` | `:unauthorized_client` | `401` | `"This client is not authorized to use the requested grant type"` |
| `Error.invalid_grant` | `:invalid_grant` | `400` | `"The authorization code is invalid or expired."` |
| `Error.unsupported_grant_type` | `:unsupported_grant_type` | `400` | `"Invalid or unknown grant type"` |
| `Error.invalid_scope` | `:invalid_scope` | `400` | `"Invalid scope value in the request"` |
| `Error.invalid_redirect_uri` | `:invalid_redirect_uri` | `400` | `"Invalid redirect uri"` |
| `Error.invalid_state` | `:invalid_state` | `400` | `"Invalid state"` |
| `Error.invalid_response_type` | `:invalid_response_type` | `400` | `"The response type is invalid."` |
| `Error.owner_credentials` | `:owner_credentials` | `400` | `"Invalid owner credentials"` |
| `Error.access_denied` | `:access_denied` | `400` | `"The user or authorization server denied the request"` |
| `Error.unsupported_token_type` | `:unsupported_token_type` | `400` | `"The authorization server does not support the presented token type"` |
| `Error.invalid_token` | `:invalid_token` | `400` | `"The token is invalid or expired"` |
| `Error.authorization_pending` | `:authorization_pending` | `400` | `"The authorization request is still pending; the client should retry the request"` |
| `Error.slow_down` | `:slow_down` | `400` | `"The client is polling too frequently and should slow down"` |
| `Error.expired_token` | `:expired_token` | `400` | `"The device code has expired; the client should request a new device authorization"` |
| `Error.expired_challenge` | `:expired_challenge` | `400` | `"The challenge has expired; the client should request a new challenge"` |
| `Error.invalid_request_uri` | `:invalid_request_uri` | `400` | `"The request_uri is invalid, expired, or does not exist"` |
| `Error.invalid_request_object` | `:invalid_request_object` | `400` | `"The request object is invalid or malformed"` |

---

## 2. Resource Server Bearer Error Responses (RFC 6750)

`Authly::Handler::Bearer` and `Authly::Handler::RequireScope` return RFC 6750 `WWW-Authenticate` challenges with `Cache-Control: no-store`:

| Condition | HTTP Status | `WWW-Authenticate` Header | JSON Body |
| :--- | :--- | :--- | :--- |
| Missing `Authorization` header or non-Bearer scheme | `401` | `Bearer realm="<realm>"` | `{}` |
| Malformed header, multiple token sources, or empty token | `400` | `Bearer realm="<realm>", error="invalid_request"` | `{"error":"invalid_request","error_description":"The request is malformed"}` |
| Invalid signature, expired, revoked, wrong `aud`/`iss`, or refresh token | `401` | `Bearer realm="<realm>", error="invalid_token"` | `{"error":"invalid_token","error_description":"The access token is invalid, expired or revoked"}` |
| Token lacks required scope | `403` | `Bearer realm="<realm>", error="insufficient_scope", scope="<scopes>"` | `{"error":"insufficient_scope","error_description":"The access token does not grant the required scope"}` |
| `TokenStore` raises `Authly::StoreUnavailable` or `IO::Error` | `503` | *(none; `Retry-After: 1`)* | `{"error":"temporarily_unavailable","error_description":"The token store is unavailable"}` |
