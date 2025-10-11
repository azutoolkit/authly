require "../spec_helper"

describe Authly::DiscoveryHandler do
  it "returns OpenID Connect discovery metadata" do
    Authly.config.base_url = "https://auth.example.com"

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    request = HTTP::Request.new("GET", "/.well-known/openid-configuration")
    context = HTTP::Server::Context.new(request, response)

    Authly::DiscoveryHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    # Parse the JSON response
    metadata = JSON.parse(result.split("\r\n\r\n")[1])

    metadata["issuer"].should eq("https://auth.example.com")
    metadata["authorization_endpoint"].should eq("https://auth.example.com/oauth/authorize")
    metadata["token_endpoint"].should eq("https://auth.example.com/oauth/token")
    metadata["userinfo_endpoint"].should eq("https://auth.example.com/oauth/userinfo")
    metadata["jwks_uri"].should eq("https://auth.example.com/.well-known/jwks.json")
    metadata["registration_endpoint"].should eq("https://auth.example.com/oauth/register")
  end

  it "includes supported grant types" do
    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    request = HTTP::Request.new("GET", "/.well-known/openid-configuration")
    context = HTTP::Server::Context.new(request, response)

    Authly::DiscoveryHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    metadata = JSON.parse(result.split("\r\n\r\n")[1])
    grant_types = metadata["grant_types_supported"].as_a.map(&.as_s)

    grant_types.should contain("authorization_code")
    grant_types.should contain("client_credentials")
    grant_types.should contain("password")
    grant_types.should contain("refresh_token")
    grant_types.should contain("urn:ietf:params:oauth:grant-type:device_code")
  end

  it "includes supported scopes" do
    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    request = HTTP::Request.new("GET", "/.well-known/openid-configuration")
    context = HTTP::Server::Context.new(request, response)

    Authly::DiscoveryHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    metadata = JSON.parse(result.split("\r\n\r\n")[1])
    scopes = metadata["scopes_supported"].as_a.map(&.as_s)

    scopes.should contain("openid")
    scopes.should contain("profile")
    scopes.should contain("email")
    scopes.should contain("address")
    scopes.should contain("phone")
  end

  it "includes PKCE methods" do
    Authly.config.enforce_pkce_s256 = false

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    request = HTTP::Request.new("GET", "/.well-known/openid-configuration")
    context = HTTP::Server::Context.new(request, response)

    Authly::DiscoveryHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    metadata = JSON.parse(result.split("\r\n\r\n")[1])
    pkce_methods = metadata["code_challenge_methods_supported"].as_a.map(&.as_s)

    pkce_methods.should contain("S256")
    pkce_methods.should contain("plain")
  end

  it "excludes plain method when S256 is enforced" do
    Authly.config.enforce_pkce_s256 = true

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    request = HTTP::Request.new("GET", "/.well-known/openid-configuration")
    context = HTTP::Server::Context.new(request, response)

    Authly::DiscoveryHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    metadata = JSON.parse(result.split("\r\n\r\n")[1])
    pkce_methods = metadata["code_challenge_methods_supported"].as_a.map(&.as_s)

    pkce_methods.should contain("S256")
    pkce_methods.should_not contain("plain")

    # Reset for other tests
    Authly.config.enforce_pkce_s256 = false
  end

  it "includes supported algorithms" do
    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    request = HTTP::Request.new("GET", "/.well-known/openid-configuration")
    context = HTTP::Server::Context.new(request, response)

    Authly::DiscoveryHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    metadata = JSON.parse(result.split("\r\n\r\n")[1])
    algorithms = metadata["id_token_signing_alg_values_supported"].as_a.map(&.as_s)

    algorithms.should contain("HS256")
    algorithms.should contain("RS256")
    algorithms.should contain("ES256")
  end
end
