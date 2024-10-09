# Authly - Simplify Authentication for Your Application

![Authly Logo](images/authly-logo.png)

[![Build Status](https://img.shields.io/github/actions/workflow/status/yourusername/authly/build.yml)](https://github.com/yourusername/authly/actions) [![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

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
    github: yourusername/authly
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

Project Link: [https://github.com/yourusername/authly](https://github.com/yourusername/authly)

## Acknowledgments

- [Best-README-Template](https://github.com/othneildrew/Best-README-Template)
- [Readme Best Practices](https://github.com/jehna/readme-best-practices)
- [Shields.io](https://shields.io) for the beautiful badges
- [GitHub Pages](https://pages.github.com) for hosting project documentation
