---
description: Harden OAuth 2.0 flows with PKCE S256 enforcement, Pushed Authorization Requests (PAR), JARM, and mTLS Certificate-Bound Tokens.
icon: lock
---

# Enable FAPI & Advanced Security (PKCE, PAR, JARM, mTLS)

This guide shows how to configure Authly's **Financial-grade API (FAPI)** and **OAuth 2.0 Security Best Current Practice** features.

---

## 1. Enforce PKCE with `S256`

Require Proof Key for Code Exchange (RFC 7636) on all `authorization_code` grants and reject the `plain` challenge method:

```crystal title="src/config/authly.cr"
Authly.configure do |config|
  config.enforce_pkce = true
  config.enforce_pkce_s256 = true
end
```

---

## 2. Require Pushed Authorization Requests (PAR / RFC 9126)

Move authorization request parameters from front-channel browser URLs to an authenticated back-channel `POST /oauth/par` call:

```crystal title="src/config/authly.cr"
Authly.configure do |config|
  config.par_ttl = 90.seconds
  config.require_par = true
end
```

{% tabs %}
{% tab title="Step 1: Back-Channel Push (POST /oauth/par)" %}
```http
POST /oauth/par HTTP/1.1
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

response_type=code&redirect_uri=https://app.example.com/cb&scope=openid+read&state=xyz&code_challenge=CHALLENGE&code_challenge_method=S256
```

Response (`201 Created`):

```json
{
  "request_uri": "urn:ietf:params:oauth:request_uri:4a8b9c...",
  "expires_in": 90
}
```
{% endtab %}

{% tab title="Step 2: Front-Channel Redirect (GET /oauth/authorize)" %}
```http
GET /oauth/authorize?client_id=CLIENT_ID&request_uri=urn:ietf:params:oauth:request_uri:4a8b9c...
```
{% endtab %}
{% endtabs %}

---

## 3. Enable JWT Secured Authorization Response Mode (JARM / RFC 9101)

Sign and optionally encrypt authorization responses (`query.jwt`, `fragment.jwt`, `form_post.jwt`, `jwt`) so authorization codes and states cannot be tampered with or leaked in redirect parameters:

```crystal title="src/config/authly.cr"
Authly.configure do |config|
  config.jarm_signing_key = File.read("jarm_private.pem")
  config.jarm_signing_alg = JWT::Algorithm::RS256

  # Optional JWE encryption
  config.jarm_encryption_key = File.read("client_encryption_public.pem")
  config.jarm_encryption_alg = "RSA-OAEP-256"
  config.jarm_encryption_enc = "A256GCM"

  config.default_jarm_response_mode = "query.jwt"
  config.jarm_lifetime = 10.minutes
end
```

---

## 4. Bind Access Tokens to Client TLS Certificates (mTLS / RFC 8705)

Bind access tokens to the SHA-256 thumbprint (`cnf.x5t#S256`) of the client's mutual TLS certificate:

{% tabs %}
{% tab title="Authly Configuration" %}
```crystal title="src/config/authly.cr"
Authly.configure do |config|
  config.require_certificate_bound_tokens = true
  config.trusted_ca_certificates = [
    File.read("/etc/ssl/certs/client-ca.pem"),
  ]
end
```
{% endtab %}

{% tab title="Nginx Reverse Proxy" %}
```nginx title="/etc/nginx/conf.d/authly.conf"
server {
    listen 443 ssl;
    ssl_client_certificate /etc/ssl/certs/client-ca.pem;
    ssl_verify_client on;

    location / {
        proxy_pass http://authly_upstream;
        proxy_set_header X-Client-Certificate $ssl_client_raw_cert;
    }
}
```
{% endtab %}
{% endtabs %}
