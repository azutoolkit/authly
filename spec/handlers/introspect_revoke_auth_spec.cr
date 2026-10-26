require "../spec_helper"

module IntrospectRevokeSpec
  extend self

  record Answer, status : Int32, headers : HTTP::Headers, body : String

  def post(path : String, form : Hash(String, String), basic : String? = nil) : Answer
    headers = HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"}
    headers["Authorization"] = "Basic #{Base64.strict_encode(basic)}" if basic
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
end
