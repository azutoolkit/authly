[![Build Status](https://travis-ci.com/eliasjpr/authly.svg?branch=master)](https://travis-ci.com/eliasjpr/authly)

# Authly

### OAuth2 Provider Library for the Crystal Language.

The OAuth 2.0 specification is a flexibile authorization framework that describes a number of grants (“methods”) for a client application to acquire an access token (which represents a user’s permission for the client to access their data) which can be used to authenticate a request to an API endpoint.

The specification describes five grants for acquiring an access token:

- Authorization code grant
- Implicit grant
- Resource owner credentials grant
- Client credentials grant
- Refresh token grant

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     authly:
       github: eliasjpr/authly
   ```

2. Run `shards install`

## Usage

```crystal
require "authly"
```

Define the `client` and `user` procs that performa the authentication checks.

Encryption secret key

```crystal
Authly.secret = "Some secret"
```

Setup Resource Server (Client) and Resource Owner (Owner)

```crystal
Authly.client = ->(client_id : String, client_secret : String, redirect_uri : String) { true | false }
Authly.owner = ->(username : String, password : String) { true | false }
```

Required for Authorization Code Grant

```crystal
Authly.code(code : CodeRequest)
```

Perform Authorization

```crystal
Authly.authorize(
    grant_type,
    client_id,
    client_secret,
    redirect_uri,
    code,
    scope,
    state,
    username,
    password,
    refresh_token
  )
```

### Exceptions

Authly returns exceptions according to the OAuth2 protocol of type `OAuthError` with `code`, `type` and `message` properties.

**Error Type and Messages**

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

- [Elias Perez](https://github.com/your-github-user) - creator and maintainer
