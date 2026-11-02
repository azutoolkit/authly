---
description: Sign tokens with RS256/ES256, rotate signing keys with zero downtime, and publish /.well-known/jwks.json.
icon: rotate
---

# Configure Asymmetric Keys, Key Rotation & JWKS

By default, Authly signs JWTs with `HS256` using a symmetric `secret_key`. When Resource Servers are separate services or third parties verify ID tokens, configure **asymmetric signing** (`RS256`, `ES256`, etc.) and publish public keys at `/.well-known/jwks.json`.

---

## 1. Configure a Single Asymmetric Key Pair (`RS256` or `ES256`)

```crystal title="src/config/authly.cr"
Authly.configure do |config|
  config.algorithm = JWT::Algorithm::RS256
  config.secret_key = File.read("keys/rsa_private.pem")
  config.public_key = File.read("keys/rsa_public.pem")
end
```

{% hint style="info" %}
**Private Keys Are Never Published**
`Authly::JWKS` strictly parses DER SubjectPublicKeyInfo structures and verifies that the public key matches `config.algorithm`. If `public_key` accidentally contains a private key or mismatched key type, `/.well-known/jwks.json` refuses to publish it (`500`).
{% endhint %}

---

## 2. Zero-Downtime Signing Key Rotation

To rotate asymmetric keys without invalidating unexpired tokens signed by the retiring key:

{% stepper %}
{% step %}
### Add New & Retiring Public Keys to `verification_keys`

Map each key ID (`kid`) to its public PEM in `config.verification_keys`.
{% endstep %}

{% step %}
### Switch `signing_key_id` & `secret_key` to the Active Key

Set `config.signing_key_id` to the active `kid` and `config.secret_key` to the active private key PEM:

```crystal title="src/config/authly.cr" lineNumbers="true"
Authly.configure do |config|
  config.algorithm = JWT::Algorithm::RS256

  # Active signing key
  config.signing_key_id = "2026-11-key"
  config.secret_key = File.read("keys/2026-11-private.pem")

  # Active + retiring verification public keys
  config.verification_keys = {
    "2026-11-key" => File.read("keys/2026-11-public.pem"),
    "2026-10-key" => File.read("keys/2026-10-public.pem"),
  }
end
```
{% endstep %}

{% step %}
### Remove the Retiring Key After Token Expiry

Once `max(access_ttl, refresh_ttl)` has elapsed since the rotation, remove `"2026-10-key"` from `config.verification_keys`.
{% endstep %}
{% endstepper %}
