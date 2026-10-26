require "../spec_helper"

describe Authly::ClientRegistrationHandler do
  # Registration is never anonymous: these examples exercise the request handling, so the host's hook admits them
  # (the access-control examples are in client_registration_security_spec.cr).
  before_each do
    Authly.config.authenticate_registration = ->(_context : HTTP::Server::Context) { true }
    Authly.config.attempt_limiter = Authly::InMemoryAttemptLimiter.new
  end
  after_each { Authly.config.authenticate_registration = nil }

  it "returns error when dynamic registration is disabled" do
    Authly.config.allow_dynamic_registration = false

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    body = {redirect_uris: ["https://example.com/callback"]}.to_json
    request = HTTP::Request.new("POST", "/oauth/register", body: body)
    context = HTTP::Server::Context.new(request, response)

    Authly::ClientRegistrationHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    result.should contain("access_denied")
    result.should contain("Dynamic client registration is not enabled")
  end

  it "registers a new client successfully" do
    Authly.config.allow_dynamic_registration = true

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    body = {
      redirect_uris:  ["https://example.com/callback"],
      client_name:    "Test App",
      grant_types:    ["authorization_code", "refresh_token"],
      response_types: ["code"],
    }.to_json
    request = HTTP::Request.new("POST", "/oauth/register", body: body)
    context = HTTP::Server::Context.new(request, response)

    Authly::ClientRegistrationHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    # Extract JSON from response
    response_body = result.split("\r\n\r\n")[1]
    client_response = JSON.parse(response_body)

    client_response["client_id"]?.should_not be_nil
    client_response["client_secret"]?.should_not be_nil
    client_response["client_name"].as_s.should eq("Test App")
    client_response["redirect_uris"].as_a.first.as_s.should eq("https://example.com/callback")

    # Verify client was stored
    stored_client = Authly.config.client_store.fetch(client_response["client_id"].as_s)
    stored_client.should_not be_nil

    # Reset
    Authly.config.allow_dynamic_registration = false
  end

  it "returns error when redirect_uris is missing" do
    Authly.config.allow_dynamic_registration = true

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    body = {client_name: "Test App"}.to_json
    request = HTTP::Request.new("POST", "/oauth/register", body: body)
    context = HTTP::Server::Context.new(request, response)

    Authly::ClientRegistrationHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    result.should contain("invalid_request")
    result.should contain("redirect_uris is required")

    # Reset
    Authly.config.allow_dynamic_registration = false
  end

  it "returns error for empty request body" do
    Authly.config.allow_dynamic_registration = true

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    request = HTTP::Request.new("POST", "/oauth/register", body: "")
    context = HTTP::Server::Context.new(request, response)

    Authly::ClientRegistrationHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    result.should contain("invalid_request")
    result.should contain("Request body is required")

    # Reset
    Authly.config.allow_dynamic_registration = false
  end

  it "returns error for invalid JSON" do
    Authly.config.allow_dynamic_registration = true

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    body = "not valid json {"
    request = HTTP::Request.new("POST", "/oauth/register", body: body)
    context = HTTP::Server::Context.new(request, response)

    Authly::ClientRegistrationHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    result.should contain("invalid_request")
    result.should contain("Invalid JSON")

    # Reset
    Authly.config.allow_dynamic_registration = false
  end

  it "creates public client when auth method is none" do
    Authly.config.allow_dynamic_registration = true

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    body = {
      redirect_uris:              ["https://example.com/callback"],
      client_name:                "Public App",
      token_endpoint_auth_method: "none",
    }.to_json
    request = HTTP::Request.new("POST", "/oauth/register", body: body)
    context = HTTP::Server::Context.new(request, response)

    Authly::ClientRegistrationHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    response_body = result.split("\r\n\r\n")[1]
    client_response = JSON.parse(response_body)

    client_response["client_id"]?.should_not be_nil
    client_response["client_secret"]?.should be_nil
    client_response["token_endpoint_auth_method"].as_s.should eq("none")

    # Reset
    Authly.config.allow_dynamic_registration = false
  end

  it "validates client metadata" do
    Authly.config.allow_dynamic_registration = true

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    body = {
      redirect_uris:  ["not a valid uri"],
      grant_types:    ["unsupported_grant_type"],
      response_types: ["code"],
    }.to_json
    request = HTTP::Request.new("POST", "/oauth/register", body: body)
    context = HTTP::Server::Context.new(request, response)

    Authly::ClientRegistrationHandler.handle(context)

    response.close
    io.rewind
    result = io.gets_to_end

    result.should contain("invalid_client_metadata")

    # Reset
    Authly.config.allow_dynamic_registration = false
  end
end
