---
description: Enable RFC 7591 Dynamic Client Registration and RFC 8628 Device Authorization with rate-limiting protection.
icon: tv
---

# Configure Dynamic Client Registration & Device Flow

This guide explains how to enable **OAuth 2.0 Dynamic Client Registration (RFC 7591)** and **Device Authorization Grant (RFC 8628)** with rate-limiting protection.

---

## 1. Enable Dynamic Client Registration (`POST /oauth/register`)

{% hint style="warning" %}
**Registration Is Never Anonymous**
Even when `allow_dynamic_registration = true`, you must configure `registration_access_token`, `authenticate_registration`, or both. Without at least one, `POST /oauth/register` responds `500` and registers nothing.
{% endhint %}

```crystal title="src/config/authly.cr" lineNumbers="true"
Authly.configure do |config|
  config.allow_dynamic_registration = true
  config.client_store = Authly::InMemoryClientStore.new

  # Require an Initial Access Token (Bearer) OR a custom authentication proc
  config.registration_access_token = ENV["AUTHLY_REGISTRATION_TOKEN"]
  config.authenticate_registration = ->(ctx : HTTP::Server::Context) {
    ctx.request.headers["X-Internal-Admin"]? == "true"
  }

  # Allowlists for client metadata
  config.registration_grant_types = ["authorization_code", "refresh_token", "challenge_response"]
  config.registration_response_types = ["code"]
  config.registration_scopes = ["openid", "profile", "read", "write"]

  # Abuse protection
  config.registration_max_body = 16 * 1024
  config.registration_rate_limit = 10
  config.registration_rate_window = 1.hour
end
```

<details>
<summary>Example <code>POST /oauth/register</code> Request & Response</summary>

```http
POST /oauth/register HTTP/1.1
Authorization: Bearer <AUTHLY_REGISTRATION_TOKEN>
Content-Type: application/json

{
  "client_name": "Mobile App",
  "redirect_uris": ["com.example.mobile:/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile read",
  "token_endpoint_auth_method": "none"
}
```

Response (`201 Created`):

```json
{
  "client_id": "client_abcdef123456",
  "client_id_issued_at": 1700000000,
  "client_secret_expires_at": 0,
  "redirect_uris": ["com.example.mobile:/callback"],
  "client_name": "Mobile App",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```
</details>

---

## 2. Enable Device Authorization Flow (`/oauth/device/code` & `/device`)

```crystal title="src/config/authly.cr" lineNumbers="true"
Authly.configure do |config|
  # Required so the user can approve the user_code at GET/POST /device
  config.authenticate_user = ->(ctx : HTTP::Server::Context) { MySession.user_id(ctx) }
  config.login_url = ->(ctx : HTTP::Server::Context) { "/login?return_to=#{URI.encode_www_form(ctx.request.resource)}" }

  # Rate limit user_code lookups at /device
  config.device_attempt_limit = 10
  config.device_attempt_window = 15.minutes

  # Behind a trusted reverse proxy that overwrites X-Real-IP:
  config.attempt_source = ->(ctx : HTTP::Server::Context) {
    ctx.request.headers["X-Real-IP"]?
  }
end
```

{% tabs %}
{% tab title="1. Request Device Code" %}
```bash
curl -X POST http://localhost:8080/oauth/device/code \
  -d "client_id=1&scope=read"
```
{% endtab %}

{% tab title="2. Poll Token Endpoint" %}
```bash
curl -X POST http://localhost:8080/oauth/token \
  -u "1:secret" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=<DEVICE_CODE>"
```
{% endtab %}
{% endtabs %}
