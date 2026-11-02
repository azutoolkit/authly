---
description: Production-ready OAuth 2.0, OpenID Connect, and FAPI authentication library for Crystal.
icon: shield-halved
---

# Welcome to Authly

**Authly** is a strongly-typed, zero-framework Crystal shard for building **OAuth 2.0**, **OpenID Connect (OIDC)**, and **Financial-grade API (FAPI)** Authorization Servers and Resource Servers on top of Crystal's standard `HTTP::Handler`.

---

## Documentation Sections

<table data-view="cards">
<thead>
<tr>
<th></th>
<th></th>
<th data-hidden data-card-target data-type="content-ref"></th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>🎓 Tutorials</strong></td>
<td>Step-by-step guided lessons that take you from a blank Crystal project to a working OAuth2 server and protected API.</td>
<td><a href="tutorials/README.md">tutorials/README.md</a></td>
</tr>
<tr>
<td><strong>🛠️ How-To Guides</strong></td>
<td>Goal-oriented recipes for Redis stores, scope enforcement, PAR, JARM, mTLS, key rotation, and Dynamic Client Registration.</td>
<td><a href="how-to/README.md">how-to/README.md</a></td>
</tr>
<tr>
<td><strong>📖 Reference</strong></td>
<td>Complete technical specifications for <code>Authly::Configuration</code>, HTTP endpoints, Crystal interfaces, and error codes.</td>
<td><a href="reference/README.md">reference/README.md</a></td>
</tr>
<tr>
<td><strong>💡 Explanation</strong></td>
<td>Deep dives into Authly's architecture, refresh token rotation families, atomic single-use credentials, and threat model.</td>
<td><a href="explanation/README.md">explanation/README.md</a></td>
</tr>
</tbody>
</table>

---

## Quick Installation

{% tabs %}
{% tab title="shard.yml" %}
```yaml title="shard.yml"
dependencies:
  authly:
    github: azutoolkit/authly
```
{% endtab %}

{% tab title="Terminal" %}
```bash
shards install
```
{% endtab %}
{% endtabs %}

---

## Capabilities at a Glance

| Category | Supported Specifications & Features |
| :--- | :--- |
| **OAuth 2.0 Grants** | Authorization Code (`authorization_code`), PKCE (`S256` / `plain`), Client Credentials (`client_credentials`), Refresh Token (`refresh_token`), Device Authorization (`urn:ietf:params:oauth:grant-type:device_code`), Cryptographic Challenge-Response (`challenge_response` / `urn:ietf:params:oauth:grant-type:challenge`), Password (`password`), Implicit (`implicit`) |
| **OpenID Connect** | ID Tokens, UserInfo Endpoint (`/oauth/userinfo`), OIDC Discovery (`/.well-known/openid-configuration`), RFC 8414 Metadata (`/.well-known/oauth-authorization-server`), JWKS (`/.well-known/jwks.json`) |
| **FAPI & Hardening** | Pushed Authorization Requests (PAR / RFC 9126), JWT Secured Authorization Response Mode (JARM / RFC 9101), Certificate-Bound mTLS Tokens (`cnf.x5t#S256` / RFC 8705), Dynamic Client Registration (RFC 7591) |
| **Resource Protection** | `Authly::Handler::Bearer` (RFC 6750), `Authly::Handler::RequireScope` (`all` / `any`), Audience (`aud`) verification, JWT & Opaque token strategies |

---

## Start Building

{% content-ref url="tutorials/getting-started.md" %}
[getting-started.md](tutorials/getting-started.md)
{% endcontent-ref %}

{% content-ref url="tutorials/challenge-response-auth.md" %}
[challenge-response-auth.md](tutorials/challenge-response-auth.md)
{% endcontent-ref %}
