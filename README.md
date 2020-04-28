# Authly

## OAuth2 Provider Library for the Crystal Language.

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

### Configuration

```crystal
# Load Clients
Authly.clients << Authly::Client.new("example", "secret", "https://www.example.com/callback", "1")

# Configure
Authly.configure do |c|
  # Secret Key for JWT Tokens
  c.secret = "Some Secret"

  # Refresh Token Time To Live
  c.refresh_ttl = 1.hour

  # Authorization Code Time To Live
  c.code_ttl = 1.hour

  # Access Token Time To Live
  c.access_ttl = 1.hour

  # Setup Owner validation check
  # Using your own ORM
  c.owner = ->User.valid?(username, password)
end
```

Perform Authorizations

```crystal

Authly.authorize(*all_args)

# Or do it yourself

Authly::ClientCredentials.new(client_id, client_secret, scope).authorize!
Authly::AuthorizationCode.new(client_id, client_secret, redirect_uri, code, scope, state).authorize!
Authly::Password.new(client_id, client_secret, username, password, scope).authorize!
Authly::RefreshToken.new(client_id, client_secret, refresh_token, scope).authorize!
Authly::Implicit.new(client_id, redirect_uri, scope, state).authorize!
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
