<div style="text-align:center"><img src="https://raw.githubusercontent.com/azutoolkit/authly/master/authly.png" /></div>

# Authly

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/747eef2e02594d40b63c9f05c6b94cd9)](https://app.codacy.com/manual/eliasjpr/authly?utm_source=github.com&utm_medium=referral&utm_content=eliasjpr/authly&utm_campaign=Badge_Grade_Settings) ![Crystal CI](https://github.com/eliasjpr/authly/workflows/Crystal%20CI/badge.svg?branch=master)

## OAuth2 Provider Server Library for the Crystal Language

Authly is an OAuth2 Library for creating Authorization Servers that supports OAuth2 authorization mechanisms. Example OAuth 2.0 Server Implementation https://github.com/azutoolkit/authority/

> Authly implements the OAuth 2.0 specification as described at https://www.oauth.com/

OAuth 2.0 is a flexibile authorization framework that describes a number of grants (“methods”) for a client application to acquire an access token (which represents a user’s permission for the client to access their data) which can be used to authenticate a request to an API endpoint.

The specification describes five grants for acquiring an access token:

- [x] Authorization code grant
- [x] Implicit grant
- [x] Resource owner credentials grant
- [x] Client credentials grant
- [x] Refresh token grant
- [x] OpenID Connect (IdToken)
- [] Device Code

## Authorization Use Cases

The first step of OAuth 2 is to get authorization from the user. For browser-based or mobile apps, this is usually accomplished by displaying an interface provided by the service to the user.

OAuth 2 provides several "grant types" for different use cases. The grant types defined are:

- **Authorization code grant** for apps running on a web server, browser-based and mobile apps
- **Resource owner credentials grant** for logging in with a username and password (only for first-party apps)
- **Client credentials** grant for application access without a user present, think microservices
- **Implicit grant** was previously recommended for clients without a secret, but has been superseded by using the Authorization Code grant with PKCE

## Terminology

### Resource owner (the user)

Entity that can grant access to a protected resource. Typically, this is the end-user.

### Resource server (the API)

Server hosting the protected resources. This is the API you want to access.

### Authorization server (can be the same server as the API)

Server that authenticates the Resource Owner and issues Access Tokens after getting proper authorization. In this case, Auth0.

### Client (the third-party app)

Application requesting access to a protected resource on behalf of the Resource Owner.

### User Agent

Agent used by the Resource Owner to interact with the Client (for example, a browser or a native application).

> **Note**
> This implementation uses JWT tokens for storage by default.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     authly:
       github: azutoolkit/authly
   ```

2. Run `shards install`

## Usage

```crystal
require "authly"
```

### Configuration

```crystal
# In memory storage of clients (3rd Party Apps)
Authly.clients << Authly::Client.new("example", "secret", "https://www.example.com/callback", "1")

#
Authly.owners << Authly::Owner.new("username", "password")

# Or use your own classes and implement interface

# Clients
class AppService
  include AuthorizableClient
end

# Owners
class UserService
  include AuthorizableOwner
end

# Configure
Authly.configure do |c|
  # Secret Key for JWT Tokens
  c.secret_key = "Some Secret"

  # Refresh Token Time To Live
  c.refresh_ttl = 1.hour

  # Authorization Code Time To Live
  c.code_ttl = 1.hour

  # Access Token Time To Live
  c.access_ttl = 1.hour

  # Using your own classes
  c.owners = UserService.new
  c.clients = AppService.new
end
```

#### Token

```crystal
Authly.access_token(grant_type, **args)
```

#### Code

```crystal
Authly.code(response_type, *args)
```

### Exceptions

Authly returns exceptions according to the OAuth2 protocol of type `Error` with `code`, `type` and `message` properties.

### Error Type and Messages

```crystal
invalid_redirect_uri:   "Invalid redirect uri",
invalid_state:          "Invalid state",
invalid_scope:          "Invalid scope value in the request",
invalid_client:         "Client authentication failed, such as if the request contains an invalid client ID or secret.",
owner_credentials:      "Invalid owner credentials",
invalid_request:        "The request is missing a parameter so the server can’t proceed with the request",
invalid_grant:          "The authorization code is invalid or expired.",
unauthorized_client:    "This client is not authorized to use the requested grant type",
unsupported_grant_type: "Invalid or unknown grant type",
access_denied:          "The user or authorization server denied the request",
```

## Contributing

1. Fork it (<https://github.com/your-github-user/authly/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Elias Perez](https://github.com/your-github-user) - Initial work
