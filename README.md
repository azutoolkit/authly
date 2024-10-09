# Authly - Simplify Authentication for Your Application

<div style="text-align:center"><img src="https://raw.githubusercontent.com/azutoolkit/authly/master/authly.png" /></div>

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/747eef2e02594d40b63c9f05c6b94cd9)](https://app.codacy.com/manual/eliasjpr/authly?utm_source=github.com&utm_medium=referral&utm_content=eliasjpr/authly&utm_campaign=Badge_Grade_Settings) ![Crystal CI](https://github.com/eliasjpr/authly/workflows/Crystal%20CI/badge.svg?branch=master)

Authly is an open-source Crystal library that helps developers integrate secure and robust authentication capabilities into their applications with ease. Supporting various OAuth2 grants and providing straightforward APIs, Authly aims to streamline the process of managing authentication in a modern software environment.

## Table of Contents

- [Authly - Simplify Authentication for Your Application](#authly---simplify-authentication-for-your-application)
  - [Table of Contents](#table-of-contents)
  - [About The Project](#about-the-project)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
  - [Usage](#usage)
    - [OAuth2 Grants](#oauth2-grants)
- [Authly::Configuration](#authlyconfiguration)
  - [Properties](#properties)
    - [`issuer : String`](#issuer--string)
    - [`secret_key : String`](#secret_key--string)
    - [`public_key : String`](#public_key--string)
    - [`refresh_ttl : Time::Span`](#refresh_ttl--timespan)
    - [`code_ttl : Time::Span`](#code_ttl--timespan)
    - [`access_ttl : Time::Span`](#access_ttl--timespan)
    - [`owners : AuthorizableOwner`](#owners--authorizableowner)
    - [`clients : AuthorizableClient`](#clients--authorizableclient)
    - [`token_store : TokenStore`](#token_store--tokenstore)
    - [`algorithm : JWT::Algorithm`](#algorithm--jwtalgorithm)
    - [`token_strategy : Symbol`](#token_strategy--symbol)
  - [Example Usage](#example-usage)
    - [Endpoints](#endpoints)
    - [Example Usage With Built In Server Handler](#example-usage-with-built-in-server-handler)
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

![Authly Demo](images/demo.gif)

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

# Authly::Configuration

The `Authly::Configuration` class is designed to hold configuration settings for the Authly authentication framework. It allows users to customize various aspects of the authentication process, including issuer details, token management, and security settings.

## Properties

### `issuer : String`

- **Default**: `"The Authority Server Provider"`
- **Description**: The identifier for the authority server provider. This is usually a unique string that represents the service that issues tokens.

### `secret_key : String`

- **Default**: A randomly generated hexadecimal string (16 bytes).
- **Description**: The secret key used for signing tokens. It should be kept secure and confidential.

### `public_key : String`

- **Default**: A randomly generated hexadecimal string (16 bytes).
- **Description**: The public key used for verifying signed tokens. This can be shared with clients for validation purposes.

### `refresh_ttl : Time::Span`

- **Default**: `1.day`
- **Description**: The time-to-live (TTL) for refresh tokens. This defines how long a refresh token remains valid before it can no longer be used to obtain new access tokens.

### `code_ttl : Time::Span`

- **Default**: `5.minutes`
- **Description**: The TTL for authorization codes. This specifies how long an authorization code is valid after being issued.

### `access_ttl : Time::Span`

- **Default**: `1.hour`
- **Description**: The TTL for access tokens. This indicates how long an access token can be used before it expires.

### `owners : AuthorizableOwner`

- **Default**: `Owners.new`
- **Description**: An instance of `AuthorizableOwner`, which manages ownership authorization. This typically includes logic to determine who can own resources.

### `clients : AuthorizableClient`

- **Default**: `Clients.new`
- **Description**: An instance of `AuthorizableClient`, responsible for managing client authorization. This may include logic for client registration and validation.

### `token_store : TokenStore`

- **Default**: `InMemoryStore.new`
- **Description**: The token storage mechanism. This specifies where tokens are stored (e.g., in memory, database, etc.). The default implementation is an in-memory store.

### `algorithm : JWT::Algorithm`

- **Default**: `JWT::Algorithm::HS256`
- **Description**: The algorithm used to sign the JWT tokens. The default is HMAC with SHA-256, but this can be changed to other algorithms as needed.

### `token_strategy : Symbol`

- **Default**: `:jwt`
- **Description**: The strategy used for token generation. The default value is `:jwt`, indicating that JSON Web Tokens are used for authentication.

---

## Example Usage

To configure your Authly setup, you can instantiate the `Configuration` class and set the desired properties:

```crystal
Authly.configure do |c|
  c.issuer= "The Authority Server Provider"
  c.secret_key= Random::Secure.hex(16)
  c.public_key= Random::Secure.hex(16)
  c.refresh_ttl = 1.day
  c.code_ttl = 5.minutes
  c.access_ttl = 1.hour
  c.owners =  Owners.new
  c.clients= Clients.new
  c.token_store= InMemoryStore.new
  c.algorithm = JWT::Algorithm::HS256
  c.token_strategy = :jwt
end
```

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

### Example Usage With Built In Server Handler

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
- [x] Support OpenID Connect for extended authentication features.
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

[Elias Perez](https://github.com/eliasjpr) - Initial work
Project Link: [https://github.com/azutoolkit/authly](https://github.com/azutoolkit/authly)

## Acknowledgments

- [Best-README-Template](https://github.com/othneildrew/Best-README-Template)
- [Readme Best Practices](https://github.com/jehna/readme-best-practices)
- [Shields.io](https://shields.io) for the beautiful badges
- [GitHub Pages](https://pages.github.com) for hosting project documentation
