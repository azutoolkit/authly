---
description: Configure Google, GitHub, Apple, Microsoft, Discord, and custom OAuth2/OIDC social sign-in flows.
icon: users
---

# Configure Social Sign-In

Authly provides built-in Social Sign-In support for **Google**, **GitHub**, **Apple**, **Microsoft / Entra ID**, **Discord**, and any custom OAuth 2.0 / OIDC identity provider (`Authly::Social::GenericOAuth2`).

It supports two complementary flows:
1. **Browser Redirect & Callback Flow** (`GET /oauth/social/:provider` and `GET|POST /oauth/social/:provider/callback`) with automatic `S256` PKCE and single-use signed CSRF `state` tokens.
2. **Token Endpoint Grant Exchange** (`POST /oauth/token` with `grant_type=social` or `urn:ietf:params:oauth:grant-type:social`) for native mobile apps, SPAs, and backend services.

---

## 1. Register Social Providers

{% tabs %}
{% tab title="Google, GitHub & Apple" %}
```crystal
Authly.configure do |config|
  config.register_social_provider(
    Authly::Social::Google.new(
      client_id: ENV["GOOGLE_CLIENT_ID"],
      client_secret: ENV["GOOGLE_CLIENT_SECRET"],
      redirect_uri: "https://auth.example.com/oauth/social/google/callback"
    )
  )

  config.register_social_provider(
    Authly::Social::GitHub.new(
      client_id: ENV["GITHUB_CLIENT_ID"],
      client_secret: ENV["GITHUB_CLIENT_SECRET"],
      redirect_uri: "https://auth.example.com/oauth/social/github/callback"
    )
  )

  config.register_social_provider(
    Authly::Social::Apple.new(
      client_id: ENV["APPLE_SERVICE_ID"],
      client_secret: ENV["APPLE_CLIENT_SECRET"],
      redirect_uri: "https://auth.example.com/oauth/social/apple/callback"
    )
  )
end
```
{% endtab %}

{% tab title="Microsoft, Discord & Custom Provider" %}
```crystal
Authly.configure do |config|
  config.register_social_provider(
    Authly::Social::Microsoft.new(
      client_id: ENV["MS_CLIENT_ID"],
      client_secret: ENV["MS_CLIENT_SECRET"],
      redirect_uri: "https://auth.example.com/oauth/social/microsoft/callback",
      tenant: "common"
    )
  )

  config.register_social_provider(
    Authly::Social::Discord.new(
      client_id: ENV["DISCORD_CLIENT_ID"],
      client_secret: ENV["DISCORD_CLIENT_SECRET"],
      redirect_uri: "https://auth.example.com/oauth/social/discord/callback"
    )
  )

  config.register_social_provider(
    Authly::Social::GenericOAuth2.new(
      name: "gitlab",
      client_id: ENV["GITLAB_CLIENT_ID"],
      client_secret: ENV["GITLAB_CLIENT_SECRET"],
      redirect_uri: "https://auth.example.com/oauth/social/gitlab/callback",
      authorize_endpoint: "https://gitlab.com/oauth/authorize",
      token_endpoint: "https://gitlab.com/oauth/token",
      userinfo_endpoint: "https://gitlab.com/oauth/userinfo"
    )
  )
end
```
{% endtab %}
{% endtabs %}

---

## 2. Map Social Profiles to Local Resource Owners

When a user completes social sign-in, Authly normalizes their upstream identity into an `Authly::SocialProfile` (`provider`, `uid`, `email`, `email_verified?`, `name`, `first_name`, `last_name`, `nickname`, `avatar_url`, `raw_attributes`).

You can map `SocialProfile` to a local subject ID either on your `AuthorizableOwner` store or via `config.social_owner_resolver`:

{% tabs %}
{% tab title="config.social_owner_resolver" %}
```crystal
Authly.configure do |config|
  config.social_owner_resolver = ->(profile : Authly::SocialProfile) : String? {
    # Find or provision a user in your database
    user = UserRepo.find_by_social(profile.provider, profile.uid)
    if user.nil? && profile.email_verified?
      if email = profile.email
        user = UserRepo.find_or_create_by_email(email, name: profile.name, avatar: profile.avatar_url)
        UserRepo.link_social(user.id, profile.provider, profile.uid)
      end
    end
    user.try(&.id)
  }
end
```
{% endtab %}

{% tab title="AuthorizableOwner#resolve_social_owner" %}
```crystal
class DatabaseOwners
  include Authly::AuthorizableOwner

  def resolve_social_owner(profile : Authly::SocialProfile) : String?
    UserRepo.resolve_or_create_from_social(profile)
  end

  # ... authorized? and id_token ...
end
```
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
**Fail-Closed Account Linking**: Only auto-link a social account to an existing email address when `profile.email_verified?` is `true`. If `resolve_social_owner` returns `nil`, Authly refuses the login with `403 access_denied`.
{% endhint %}

---

## 3. Flow A: Browser Redirect & Callback (`/oauth/social/:provider`)

1. **Direct Sign-In**: Redirect the browser to `GET /oauth/social/google?scope=read+openid`. Upon callback at `/oauth/social/google/callback`, Authly verifies the signed `state` token, consumes its single-use nonce in `state_store`, exchanges the `code` with PKCE `code_verifier`, and returns `200 OK` JSON with an `AccessToken` (or invokes `config.on_social_authenticated` to set your app's session cookie).
2. **OAuth2 Client Code Flow**: Pass `client_id`, `redirect_uri`, `scope`, and `state` to `GET /oauth/social/google?client_id=my-app&redirect_uri=https://app.example.com/cb&scope=read+openid&state=xyz`. Upon callback, Authly redirects to `https://app.example.com/cb?code=<authly_code>&state=xyz`.

---

## 4. Flow B: Token Endpoint Grant Exchange (`POST /oauth/token`)

Mobile apps and SPAs that obtain an authorization `code` or `subject_token` / `id_token` directly from a social SDK can exchange it at `POST /oauth/token`:

```bash
curl -X POST https://auth.example.com/oauth/token \
  -u "my-client:my-secret" \
  -d "grant_type=social" \
  -d "provider=google" \
  -d "code=4/0AfJohXl..." \
  -d "scope=read openid"
```
