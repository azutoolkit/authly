# Authly - Simplify Authentication for Your Application

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/747eef2e02594d40b63c9f05c6b94cd9)](https://app.codacy.com/manual/eliasjpr/authly?utm_source=github.com&utm_medium=referral&utm_content=eliasjpr/authly&utm_campaign=Badge_Grade_Settings) [![Crystal CI](https://github.com/azutoolkit/authly/actions/workflows/crystal.yml/badge.svg?branch=master)](https://github.com/azutoolkit/authly/actions/workflows/crystal.yml)

<div style="text-align:center"><img src="https://raw.githubusercontent.com/azutoolkit/authly/master/authly.png" /></div>

Authly is an open-source Crystal library that helps developers integrate secure and robust authentication capabilities into their applications with ease. Supporting various OAuth2 grants and providing straightforward APIs, Authly aims to streamline the process of managing authentication in a modern software environment.

## Table of Contents

- [Authly - Simplify Authentication for Your Application](#authly---simplify-authentication-for-your-application)
  - [Table of Contents](#table-of-contents)
  - [About The Project](#about-the-project)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
  - [Usage](#usage)
    - [Configuration Setup](#configuration-setup)
    - [Custom Authorizable Client and Owner](#custom-authorizable-client-and-owner)
      - [Custom Client Example](#custom-client-example)
      - [Custom Owner Example](#custom-owner-example)
    - [Creating a Custom TokenStore](#creating-a-custom-tokenstore)
      - [Custom TokenStore Example](#custom-tokenstore-example)
    - [OAuth2 Grants](#oauth2-grants)
    - [Endpoints](#endpoints)
    - [Example Usage](#example-usage)
  - [Features](#features)
  - [Roadmap](#roadmap)
  - [Contributing](#contributing)
  - [License](#license)
  - [Contact](#contact)
  - [Acknowledgments](#acknowledgments)

## About The Project

Authly is designed to make authentication simple for developers who want to focus on building their application rather than getting bogged down in authentication logic. Authly offers:

- Support for OAuth2 grant types, including Authorization Code, Client Credentials, Password, Implicit, Device Code, and Refresh Token.
- OpenID Connect support for ID Token generation.
- A well-documented, intuitive API.
- Built-in token management with support for introspection and revocation.
- Easy-to-configure HTTP handlers for integrating authentication flows.
- Support for both opaque and JWT tokens.

## Getting Started

To get started with Authly, follow these steps to install and integrate it with your project.

### Prerequisites

- Crystal language (v1.0 or higher)
- A working development environment (Linux, macOS, or Windows)

### Installation

To install Authly, add it to your `shard.yml`:

```yaml
dependencies:
  authly:
    github: azutoolkit/authly
```

Run `shards install` to add the dependency to your project.

## Usage

### Configuration Setup

To configure Authly, you need to set up some essential configuration options for your application. These options include issuer information, secret keys, token expiration settings, and custom handlers. Here’s how you can set up the configuration:

```crystal
Authly.configure do |config|
  config.issuer = "https://your-app.com"
  config.secret_key = ENV["AUTHLY_SECRET_KEY"] # Ensure you keep this key secure
  config.public_key = ENV["AUTHLY_PUBLIC_KEY"]
  config.refresh_ttl = 1.day # Token Time-to-Live in seconds
  config.code_ttl = 5.minutes
  config.access_ttl =1.hour
  config.owners = CustomAuthorizableOwner.new
  config.clients = CustomAuthorizableClient.new
  config.token_store = CustomTokenStore.new
  config.algorithm = JWT::Algorithm::HS256
  config.token_strategy = :jwt
end
```

This configuration ensures that your application has secure, well-defined settings for token management.

### Custom Authorizable Client and Owner

Authly allows you to implement custom clients and owners to define how they are authorized within your application. You need to implement `AuthorizableClient` and `AuthorizableOwner` interfaces.

#### Custom Client Example

```crystal
class CustomAuthorizableClient
  include Authly::AuthorizableClient

  def valid_redirect?(redirect_uri : String) : Bool
    # Implement logic to verify if the provided redirect URI is valid
    valid_uris = ["https://your-app.com/callback", "https://another-allowed-url.com"]
    valid_uris.includes?(redirect_uri)
  end

  def authorized?(client_id : String, client_secret : String) : Bool
    # Implement logic to verify client credentials
    client_id == "expected_client_id" && client_secret == "expected_client_secret"
  end
end
```

#### Custom Owner Example

```crystal
class CustomAuthorizableOwner
  include Authly::AuthorizableOwner

  def authorized?(username : String, password : String) : Bool
    # Implement logic to verify user credentials
    username == "valid_user" && password == "valid_password"
  end

  def id_token(user_data : Hash(String, String)) : String
    # Create an ID Token for the user
    "user_id_token"
  end
end
```

These implementations allow your app to customize the logic for verifying clients and owners.

### Creating a Custom TokenStore

Authly comes with an in-memory token store by default, which works well for development or single-node deployments. However, for production use or when you need persistence across restarts, you can create a custom `TokenStore`.

#### Custom TokenStore Example

```crystal
class CustomTokenStore
  include Authly::TokenStore

  def store(token : String, data : Hash(String, String))
    # Store token in a database or any other persistent storage
    DB.exec("INSERT INTO tokens (token, data) VALUES (?, ?)", token, data.to_json)
  end

  def fetch(token : String) : Hash(String, String)?
    # Fetch token data from the persistent storage
    result = DB.query_one("SELECT data FROM tokens WHERE token = ?", token)
    result.not_nil! ? JSON.parse(result, Hash(String, String)) : nil
  end

  def revoke(token : String)
    # Revoke a token by removing it from the persistent storage
    DB.exec("DELETE FROM tokens WHERE token = ?", token)
  end

  def revoked?(token : String) : Bool
    # Check if a token has been revoked
    !DB.query_one("SELECT 1 FROM tokens WHERE token = ?", token).nil?
  end

  def valid?(token : String) : Bool
    # Implement logic to verify if the token is still valid
    !revoked?(token)
  end
end
```

This custom store allows for better scalability and persistence, making your authentication system robust and reliable.

### OAuth2 Grants

Authly supports several OAuth2 grant types, which can be used based on your application's authentication needs:

1. **Authorization Code Grant**: This is the most secure grant type, typically used by server-side applications where the client secret can be kept confidential. It involves an intermediate authorization code that is exchanged for an access token.
2. **Implicit Grant**: This grant type is used for public clients, such as JavaScript apps, where the access token is returned directly without an intermediate authorization code.
3. **Resource Owner Credentials Grant**: Suitable for highly trusted applications, this grant type allows the use of the resource owner's username and password directly to obtain an access token.
4. **Client Credentials Grant**: Used when the client itself is the resource owner, or when accessing its own resources. This is suitable for machine-to-machine communication.
5. **Refresh Token Grant**: Allows clients to obtain a new access token without requiring user interaction, thus improving the user experience by keeping users logged in.
6. **Device Code**: Suitable for devices that have limited input capabilities. The device code flow allows users to authenticate on a separate device with a browser.

Each of these grants can be accessed through the `/oauth/token` endpoint, with specific parameters to specify the grant type.

Authly provides an easy way to set up an authentication service in your application. Here's how to get started with its key components:

### Endpoints

Authly provides HTTP handlers to set up OAuth2 endpoints. The available endpoints include:

1. **Authorization Endpoint** (`/oauth/authorize`): Used to get authorization from the resource owner.

   ```crystal
   server = HTTP::Server.new([
     Authly::OAuthHandler.new,
   ])
   server.bind_tcp("127.0.0.1", 8080)
   server.listen
   ```

2. **Token Endpoint** (`/oauth/token`): Used to exchange an authorization grant for an access token.
3. **Introspection Endpoint** (`/introspect`): Allows clients to validate the token.
4. **Revoke Endpoint** (`/revoke`): Used to revoke an access or refresh token.

### Example Usage

To integrate Authly into your existing application, create an instance of the server with the appropriate handlers:

```crystal
require "authly"

server = HTTP::Server.new([
  Authly::OAuthHandler.new,
])
server.bind_tcp("0.0.0.0", 8080)
puts "Listening on http://0.0.0.0:8080"
server.listen
```

Once the server is running, you can send HTTP requests to authenticate users and manage tokens.

## Features

- **OAuth2 Grants**:
  - [x] Authorization Code Grant
  - [x] Implicit Grant
  - [x] Resource Owner Credentials Grant
  - [x] Client Credentials Grant
  - [x] Refresh Token Grant
  - [x] Device Code
- **OpenID Connect (ID Token)**: Generate ID tokens for user identity.
- **Token Introspection**: Allows clients to validate tokens.
- **Token Revocation**: Easy-to-use token revocation functionality to invalidate access or refresh tokens.
- **Opaque Tokens**: Support for opaque tokens in addition to JWTs.
- **Configurable Handlers**: Customizable HTTP handlers to integrate authentication endpoints into your application effortlessly.

## Roadmap

- [ ] Add more examples for integrating with front-end frameworks.
- [ ] Support OpenID Connect for extended authentication features.
- [ ] Add more customization options for token storage backends.

See the [open issues](https://github.com/yourusername/authly/issues) for a list of proposed features (and known issues).

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Contact

Elias J. Perez - [@eliasjpr](https://github.com/eliasjpr)
Project Link: [https://github.com/yourusername/authly](https://github.com/yourusername/authly)

## Acknowledgments

- [Best-README-Template](https://github.com/othneildrew/Best-README-Template)
- [Readme Best Practices](https://github.com/jehna/readme-best-practices)
- [Shields.io](https://shields.io) for the beautiful badges
- [GitHub Pages](https://pages.github.com) for hosting project documentation
