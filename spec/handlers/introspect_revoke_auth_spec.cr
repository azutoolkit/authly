require "../spec_helper"

module IntrospectRevokeSpec
  extend self

  record Answer, status : Int32, headers : HTTP::Headers, body : String

  def post(path : String, form : Hash(String, String), basic : String? = nil, authorization : String? = nil) : Answer
    headers = HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"}
    headers["Authorization"] = "Basic #{Base64.strict_encode(basic)}" if basic
    headers["Authorization"] = authorization if authorization
    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    context = HTTP::Server::Context.new(HTTP::Request.new("POST", path, headers, HTTP::Params.encode(form)), response)
    OAUTH_HANDLER.call(context)
    response.close
    Answer.new(response.status_code, response.headers, io.to_s.split("\r\n\r\n", 2).last)
  end

  # An access token issued to client "1" (secret "secret").
  def token : String
    Authly::AccessToken.new("1", "read", subject: "alice").access_token
  end

  # Runs the block with the opaque strategy (and a fresh store) behind the handlers, then puts the JWT one back.
  def with_opaque_strategy(&)
    previous = Authly::TokenManager.instance
    Authly.config.token_strategy = :opaque
    Authly.config.token_store = Authly::InMemoryStore.new
    Authly::TokenManager.instance = Authly::TokenManager.new(token_manager: Authly::OpaqueToken.new)
    yield
  ensure
    Authly::TokenManager.instance = previous
  end
end

# The handlers reach the strategy through the shared instance, built once from the configuration.
class Authly::TokenManager
  def self.instance=(@@instance : TokenManager?)
  end
end

describe "client authentication at /introspect and /revoke (RFC 7662, RFC 7009)" do
  {"/introspect", "/revoke"}.each do |path|
    it "answers #{path} without client credentials with 401 invalid_client" do
      answer = IntrospectRevokeSpec.post(path, {"token" => IntrospectRevokeSpec.token})

      answer.status.should eq 401
      answer.headers["WWW-Authenticate"].should eq %(Basic realm="authly")
      JSON.parse(answer.body)["error"].should eq "invalid_client"
    end

    it "answers #{path} with a wrong client secret with 401" do
      answer = IntrospectRevokeSpec.post(path, {"token" => IntrospectRevokeSpec.token, "client_id" => "1", "client_secret" => "wrong"})

      answer.status.should eq 401
    end
  end

  it "introspects for a client authenticated with HTTP Basic" do
    answer = IntrospectRevokeSpec.post("/introspect", {"token" => IntrospectRevokeSpec.token}, basic: "1:secret")

    answer.status.should eq 200
    JSON.parse(answer.body)["active"].should be_true
  end

  it "introspects for a client authenticated in the form body" do
    answer = IntrospectRevokeSpec.post("/introspect", {"token" => IntrospectRevokeSpec.token, "client_id" => "1", "client_secret" => "secret"})

    answer.status.should eq 200
    JSON.parse(answer.body)["sub"].should eq "alice"
  end

  it "serves both endpoints at the paths the discovery document advertises" do
    token = IntrospectRevokeSpec.token

    IntrospectRevokeSpec.post("/oauth/introspect", {"token" => token}, basic: "1:secret").status.should eq 200
    IntrospectRevokeSpec.post("/oauth/revoke", {"token" => token}, basic: "1:secret").status.should eq 200
    Authly.revoked?(token).should be_true
  end

  it "does not revoke a token for an unauthenticated caller" do
    token = IntrospectRevokeSpec.token
    IntrospectRevokeSpec.post("/revoke", {"token" => token})

    Authly.revoked?(token).should be_false
  end

  it "revokes a token for the client it was issued to" do
    token = IntrospectRevokeSpec.token
    answer = IntrospectRevokeSpec.post("/revoke", {"token" => token}, basic: "1:secret")

    answer.status.should eq 200
    Authly.revoked?(token).should be_true
  end

  it "does not let another client revoke it, and does not say so" do
    token = IntrospectRevokeSpec.token
    answer = IntrospectRevokeSpec.post("/revoke", {"token" => token}, basic: "test_client:test_secret")

    answer.status.should eq 200
    Authly.revoked?(token).should be_false
  end

  it "revokes a JWT refresh token for the client it was issued to, and not for another" do
    refresh = Authly::AccessToken.new("1", "read", subject: "alice").refresh_token.not_nil!

    IntrospectRevokeSpec.post("/revoke", {"token" => refresh}, basic: "test_client:test_secret").status.should eq 200
    Authly.revoked?(refresh).should be_false

    IntrospectRevokeSpec.post("/revoke", {"token" => refresh}, basic: "1:secret").status.should eq 200
    Authly.revoked?(refresh).should be_true
  end

  it "revokes an opaque refresh token for the client it was issued to, and not for another" do
    IntrospectRevokeSpec.with_opaque_strategy do
      refresh = Authly::AccessToken.new("1", "read", subject: "alice").refresh_token.not_nil!

      IntrospectRevokeSpec.post("/revoke", {"token" => refresh}, basic: "test_client:test_secret").status.should eq 200
      Authly.revoked?(refresh).should be_false

      IntrospectRevokeSpec.post("/revoke", {"token" => refresh}, basic: "1:secret").status.should eq 200
      Authly.revoked?(refresh).should be_true
    end
  end

  it "revokes an opaque refresh token stored before it carried a cid (the client is its sub)" do
    IntrospectRevokeSpec.with_opaque_strategy do
      Authly.config.token_store.store("legacy-refresh", {"sub" => "1", "token_type" => "refresh_token", "exp" => 1.hour.from_now.to_unix} of String => String | Int64 | Bool | Float64)

      IntrospectRevokeSpec.post("/revoke", {"token" => "legacy-refresh"}, basic: "test_client:test_secret")
      Authly.revoked?("legacy-refresh").should be_false

      IntrospectRevokeSpec.post("/revoke", {"token" => "legacy-refresh"}, basic: "1:secret")
      Authly.revoked?("legacy-refresh").should be_true
    end
  end

  it "does not let another client revoke an opaque access token" do
    IntrospectRevokeSpec.with_opaque_strategy do
      access = IntrospectRevokeSpec.token

      IntrospectRevokeSpec.post("/revoke", {"token" => access}, basic: "test_client:test_secret")
      Authly.revoked?(access).should be_false

      IntrospectRevokeSpec.post("/revoke", {"token" => access}, basic: "1:secret")
      Authly.revoked?(access).should be_true
    end
  end

  # RFC 6749 2.3: one authentication method per request, so a broken Basic header is not
  # rescued by credentials in the form.
  {"Basic !!!not-base64!!!", "Basic #{Base64.strict_encode("no-separator")}"}.each do |header|
    it "answers 401 for a malformed Basic header (#{header}) even with valid form credentials" do
      token = IntrospectRevokeSpec.token
      form = {"token" => token, "client_id" => "1", "client_secret" => "secret"}

      answer = IntrospectRevokeSpec.post("/revoke", form, authorization: header)

      answer.status.should eq 401
      JSON.parse(answer.body)["error"].should eq "invalid_client"
      Authly.revoked?(token).should be_false
      IntrospectRevokeSpec.post("/introspect", form, authorization: header).status.should eq 401
    end
  end
end
