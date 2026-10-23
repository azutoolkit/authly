require "../spec_helper"

# Echoes what a downstream handler sees; `/slow` yields to other fibers first.
class ClaimsEcho
  include HTTP::Handler

  def call(context)
    sleep 50.milliseconds if context.request.path == "/slow"
    claims = context.authly_claims
    context.response.content_type = "application/json"
    return if context.request.method == "HEAD"

    context.response.print({
      sub:    claims.try(&.subject),
      scopes: claims.try(&.scopes),
    }.to_json)
  end
end

module BearerSpec
  extend self

  def token(scope = "read:users write:users", subject = "alice") : String
    Authly::AccessToken.new("test_client", scope, subject: subject).access_token
  end

  def jwt(payload, key = Authly.config.secret_key, algorithm = JWT::Algorithm::HS256) : String
    JWT.encode(payload, key, algorithm)
  end

  def payload(overrides = {} of String => JSON::Any::Type)
    base = {
      "sub"        => "alice",
      "iss"        => Authly.config.issuer,
      "cid"        => "test_client",
      "iat"        => Time.utc.to_unix,
      "exp"        => 1.hour.from_now.to_unix,
      "scope"      => "read:users",
      "token_type" => "access_token",
      "jti"        => Random::Secure.hex(8),
    } of String => JSON::Any::Type
    base.merge(overrides)
  end

  def b64(value : String) : String
    Base64.urlsafe_encode(value, padding: false)
  end

  def with_server(handlers : Array(HTTP::Handler), &)
    server = HTTP::Server.new(handlers)
    address = server.bind_unused_port
    spawn { server.listen }
    Fiber.yield
    begin
      yield HTTP::Client.new(address.address, address.port)
    ensure
      server.close
    end
  end

  def chain : Array(HTTP::Handler)
    [
      Authly::Handler::Bearer.new(realm: "api", except: ["/public", "/health"]),
      Authly::Handler::RequireScope.all("read:users", realm: "api", prefixes: ["/users"]),
      Authly::Handler::RequireScope.any("admin", "root", realm: "api", prefixes: ["/admin"]),
      ClaimsEcho.new,
    ] of HTTP::Handler
  end

  def get(client, path, authorization : String? = nil) : HTTP::Client::Response
    headers = HTTP::Headers.new
    headers["Authorization"] = authorization if authorization
    client.get(path, headers)
  end
end
