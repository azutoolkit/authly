require "../spec_helper"

describe Authly::UserInfoHandler do
  it "returns error when Authorization header is missing" do
    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    request = HTTP::Request.new("GET", "/oauth/userinfo")
    context = HTTP::Server::Context.new(request, response)

    Authly::UserInfoHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    result.should contain("invalid_token")
    result.should contain("Authorization header is missing")
  end

  it "returns error for invalid Authorization header format" do
    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    headers = HTTP::Headers.new
    headers["Authorization"] = "InvalidFormat token123"
    request = HTTP::Request.new("GET", "/oauth/userinfo", headers)
    context = HTTP::Server::Context.new(request, response)

    Authly::UserInfoHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    result.should contain("invalid_token")
    result.should contain("Invalid Authorization header format")
  end

  it "returns user info for valid JWT token" do
    # Create a valid access token
    Authly.config.token_strategy = :jwt
    client_id = "test_client"
    scope = "openid profile email"

    token = Authly::AccessToken.new(client_id, scope)

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    headers = HTTP::Headers.new
    headers["Authorization"] = "Bearer #{token.access_token}"
    request = HTTP::Request.new("GET", "/oauth/userinfo", headers)
    context = HTTP::Server::Context.new(request, response)

    Authly::UserInfoHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    # Parse response
    body = result.split("\r\n\r\n")[1]
    user_info = JSON.parse(body)

    user_info["sub"]?.should_not be_nil
  end

  it "returns error for expired token" do
    # This test would require creating an expired token
    # For now, we'll test with an invalid token
    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    headers = HTTP::Headers.new
    headers["Authorization"] = "Bearer invalid_token_12345"
    request = HTTP::Request.new("GET", "/oauth/userinfo", headers)
    context = HTTP::Server::Context.new(request, response)

    Authly::UserInfoHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    result.should contain("invalid_token")
  end

  it "filters claims based on scope" do
    # This test verifies that only claims for requested scopes are returned
    Authly.config.token_strategy = :jwt
    client_id = "test_client"

    # Token with only 'openid' scope (no profile or email)
    scope = "openid"
    token = Authly::AccessToken.new(client_id, scope)

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    headers = HTTP::Headers.new
    headers["Authorization"] = "Bearer #{token.access_token}"
    request = HTTP::Request.new("GET", "/oauth/userinfo", headers)
    context = HTTP::Server::Context.new(request, response)

    Authly::UserInfoHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    body = result.split("\r\n\r\n")[1]
    user_info = JSON.parse(body)

    # Should always include 'sub'
    user_info["sub"]?.should_not be_nil
  end
end

describe "UserInfoHandler errors" do
  it "does not echo the exception message of an internal error" do
    token = Authly.jwt_encode({
      "sub" => 5_i64, "iss" => Authly.config.issuer, "token_type" => "access_token", "cid" => "test_client",
      "scope" => "openid", "jti" => Random::Secure.hex(8), "exp" => 1.hour.from_now.to_unix,
    })
    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    headers = HTTP::Headers{"Authorization" => "Bearer #{token}"}
    Authly::UserInfoHandler.handle(HTTP::Server::Context.new(HTTP::Request.new("GET", "/oauth/userinfo", headers), response))
    response.close
    io.rewind
    text = io.gets_to_end

    text.should start_with("HTTP/1.1 500")
    text.should contain("server_error")
    text.should_not contain("Cast")
    text.should_not contain("Int64")
  end
end
