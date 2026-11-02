---
description: Protect HTTP::Server and Azu endpoints with Authly::Handler::Bearer, RequireScope, and audience verification.
icon: shield-check
---

# Protect Resource APIs & Mount in Azu

Authly provides two standalone `HTTP::Handler` middlewares for protecting Resource Server routes:
- `Authly::Handler::Bearer` — Validates `Authorization: Bearer <token>` and populates `context.authly_claims`.
- `Authly::Handler::RequireScope` — Enforces required OAuth2 scopes on verified claims.

---

## 1. Mount `Bearer` & `RequireScope`

{% tabs %}
{% tab title="Standard HTTP::Server" %}
```crystal title="src/server.cr" lineNumbers="true"
require "http/server"
require "authly"

verifier = Authly::StrategyTokenVerifier.new(audience: "https://api.example.com")

server = HTTP::Server.new([
  Authly::Handler.new,
  Authly::Handler::Bearer.new(
    verifier,
    realm: "api",
    except_exact: ["/health", "/ready"],
    except: ["/oauth", "/.well-known"],
  ),
  Authly::Handler::RequireScope.all("billing:read", "billing:export", prefixes: ["/billing"]),
  Authly::Handler::RequireScope.any("admin", "super_admin", prefixes: ["/admin"]),
  my_app_handler,
])
```
{% endtab %}

{% tab title="Azu Framework" %}
```crystal title="src/app.cr" lineNumbers="true"
require "azu"
require "authly"

app = Azu::App.default
app.router.get "/users", UsersEndpoint.new

server = app.server([
  *app.default_handlers,
  Authly::Handler.new,
  Authly::Handler::Bearer.new(
    except_exact: ["/health"],
    except: ["/oauth", "/.well-known"],
  ),
  Authly::Handler::RequireScope.all("read:users", prefixes: ["/users"]),
] of HTTP::Handler)
```
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
**Prefer `except` and `except_exact` over `prefixes` on `Bearer`**
When `Bearer` is configured without `prefixes`, it protects **every** route except those in `except` and `except_exact`, ensuring any new top-level route added later is protected by default.
{% endhint %}

---

## 2. Read Verified Claims in Endpoints

Inside your application handler, access the verified claims via `context.authly_claims!`:

```crystal title="src/endpoints/users_endpoint.cr"
claims = context.authly_claims!
claims.subject             # String        — The `sub` claim (resource owner or client ID)
claims.client_id           # String        — The `cid` claim (client ID)
claims.scopes              # Array(String) — Granted scopes
claims.scope?("write")     # Bool          — Check if a specific scope is granted
claims["jti"].as_s         # JSON::Any     — Access any additional claim
```

---

## 3. Customize Token Audience & Claims (`IssuanceOptions`)

Use `config.issuance_options` to attach per-client audiences, custom lifetimes, or custom scalar claims at issuance time:

```crystal title="src/config/authly.cr"
Authly.configure do |config|
  config.issuance_options = ->(client_id : String, grant_type : String) {
    Authly::IssuanceOptions.new(
      audience: "https://orders.example.com",
      expires_at: 15.minutes.from_now,
      additional_claims: {"tenant_id" => "acme"} of String => Authly::AdditionalClaim,
      issue_refresh: grant_type != "client_credentials",
    )
  }
end
```
