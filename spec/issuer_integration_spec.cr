require "./spec_helper"

describe "hosted issuer integration" do
  before_each do
    Authly.config.token_store = Authly::InMemoryStore.new
    Authly.config.state_store = Authly::InMemoryStateStore.new
  end

  it "binds codes to their client even when another client shares the callback" do
    Authly.clients << Authly::Client.new("other", "secret2", AuthorizationSecuritySpec::CALLBACK, "other", "read", "authorization_code")
    code = Authly::Code.new("1", "read", AuthorizationSecuritySpec::CALLBACK).to_s
    expect_raises(Authly::Error) do
      Authly::AuthorizationCode.new("other", "secret2", AuthorizationSecuritySpec::CALLBACK, code).authorized?
    end
    Authly::AuthorizationCode.new("1", "secret", AuthorizationSecuritySpec::CALLBACK, code).authorized?.should be_true
  end

  it "rejects a signed non-code credential even with matching code fields" do
    original = Authly::Code.new("1", "read", AuthorizationSecuritySpec::CALLBACK).to_s
    claims = Authly.jwt_decode(original)[0].as_h
    claims["token_type"] = JSON::Any.new("access_token")
    expect_raises(Authly::Error) do
      Authly::AuthorizationCode.new("1", "secret", AuthorizationSecuritySpec::CALLBACK, Authly.jwt_encode(claims)).authorized?
    end
  end

  it "reads configured issuer and lifetimes when issuing credentials" do
    Authly.config.issuer = "https://issuer.example"
    Authly.config.code_ttl = 60.seconds
    Authly.config.access_ttl = 5.minutes
    code = Authly.jwt_decode(Authly::Code.new("1", "read", AuthorizationSecuritySpec::CALLBACK).to_s)[0]
    code["exp"].as_i64.-(code["iat"].as_i64).should eq 60
    token = Authly::AccessToken.new("1", "read")
    claims = Authly.jwt_decode(token.access_token)[0]
    claims["iss"].as_s.should eq "https://issuer.example"
    claims["exp"].as_i64.should eq token.expires_at
    token.expires_in.should eq 300
  end

  it "carries the OIDC nonce through consent and redemption separately from CSRF state" do
    response = AuthorizationSecuritySpec.approve(AuthorizationSecuritySpec.params(scope: "openid", nonce: "oidc-nonce"), "john")
    code = URI.parse(response.location.not_nil!).query_params["code"]
    token = Authly.access_token("authorization_code", client_id: "1", client_secret: "secret", redirect_uri: AuthorizationSecuritySpec::CALLBACK, code: code)
    claims = Authly.jwt_decode(token.id_token.not_nil!)[0]
    claims["nonce"].as_s.should eq "oidc-nonce"
    claims["aud"].as_s.should eq "1"
  end

  it "preserves machine scopes, refuses escalation, and can omit refresh tokens" do
    Authly.config.issue_refresh_tokens = false
    token = Authly.access_token("client_credentials", client_id: "1", client_secret: "secret", scope: "read write")
    token.scope.should eq "read write"
    JSON.parse(token.to_json)["refresh_token"]?.should be_nil
    expect_raises(Authly::Error) do
      Authly.access_token("client_credentials", client_id: "1", client_secret: "secret", scope: "unknown")
    end
  end

  it "applies per-issuance audience, expiry, and claims without mutating global settings" do
    deadline = Time.utc + 30.seconds
    options = Authly::IssuanceOptions.new("agent:production", deadline, {"sid" => "session-1", "browser" => true} of String => Authly::AdditionalClaim)
    token = Authly::AccessToken.new("gateway", "operations:write", subject: "account:7", options: options)
    claims = Authly.jwt_decode(token.access_token)[0]
    claims["aud"].as_s.should eq "agent:production"
    claims["exp"].as_i64.should eq deadline.to_unix
    claims["sid"].as_s.should eq "session-1"
    claims["browser"].as_bool.should be_true
    token.refresh_token.should be_nil
    Authly.config.access_ttl.should eq 1.hour
    Authly::StrategyTokenVerifier.new(audience: "other").verify(token.access_token).should be_nil
    Authly::StrategyTokenVerifier.new(audience: "agent:production").verify(token.access_token).should_not be_nil
  end

  it "refuses reserved claim overrides" do
    expect_raises(ArgumentError) do
      Authly::IssuanceOptions.new("api", Time.utc + 1.minute, {"sub" => "victim"} of String => Authly::AdditionalClaim)
    end
  end

  it "rejects disabled grants before issuing credentials" do
    Authly.config.grant_types = %w[authorization_code client_credentials]
    expect_raises(Authly::Error) do
      Authly.access_token("password", client_id: "1", client_secret: "secret", username: "john", password: "secret")
    end
  end

  it "authenticates token requests using HTTP Basic and returns standard JSON" do
    probe = AuthorizationSecuritySpec::Probe.new("POST", "/oauth/token", form: {"grant_type" => "client_credentials", "scope" => "read"})
    probe.context.request.headers["Authorization"] = "Basic #{Base64.strict_encode("1:secret")}"
    Authly::AccessTokenHandler.handle(probe.context)
    probe.status.should eq 200
    result = JSON.parse(probe.body)
    result["token_type"].as_s.should eq "Bearer"
    result["scope"].as_s.should eq "read"
    result["expires_in"].as_i64.should be > 0
  end

  it "selects only a configured signing key and accepts a retiring key" do
    Authly.config.signing_key_id = "old"
    Authly.config.verification_keys = {"old" => Authly.config.secret_key}
    token = Authly::AccessToken.new("1", "read").access_token
    Authly.config.secret_key = "new-signing-secret"
    Authly.config.signing_key_id = "new"
    Authly.config.verification_keys = Authly.config.verification_keys.merge({"new" => "new-signing-secret"})
    Authly::StrategyTokenVerifier.new.verify(token).should_not be_nil
    Authly.config.verification_keys = {"new" => "new-signing-secret"}
    Authly::StrategyTokenVerifier.new.verify(token).should be_nil
  end
end

describe "issuer extension hooks" do
  it "publishes retiring RSA keys and signs with the active kid" do
    old = OpenSSL::PKey::RSA.new(2048)
    active = OpenSSL::PKey::RSA.new(2048)
    config = Authly.config
    config.algorithm = JWT::Algorithm::RS256
    config.secret_key = active.to_pem
    config.public_key = active.public_key.to_pem
    config.signing_key_id = "active"
    config.verification_keys = {"active" => active.public_key.to_pem, "retiring" => old.public_key.to_pem}
    token = Authly::AccessToken.new("client", "read")
    Authly.jwt_decode(token.access_token)[1]["kid"].as_s.should eq "active"
    Authly::JWKS.new.keys.map(&.["kid"]).sort.should eq %w[active retiring]
    Authly::JWKS.new.to_json.should_not contain("PRIVATE")
  end

  it "lets the host render consent without bypassing approval or the CSRF token" do
    Authly.config.render_consent = ->(ctx : HTTP::Server::Context, req : Authly::AuthorizationRequest, subject : String, token : String) {
      ctx.response.content_type = "application/json"
      ctx.response << {client: req.client_id, subject: subject, consent_token: token}.to_json
      nil
    }
    page = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params(nonce: "client-nonce"), "john")
    result = JSON.parse(page.body)
    approval = AuthorizationSecuritySpec.decide({"consent_token" => result["consent_token"].as_s, "decision" => "approve"}, "john")
    approval.status.should eq 302
    replay = AuthorizationSecuritySpec.decide({"consent_token" => result["consent_token"].as_s, "decision" => "approve"}, "john")
    replay.status.should eq 400
  end

  it "loads UserInfo from the verified subject and does not let the hook replace it" do
    Authly.config.userinfo = ->(subject : String) { {"sub" => JSON::Any.new("attacker"), "email" => JSON::Any.new("person@example.test"), "email_verified" => JSON::Any.new(true)} }
    token = Authly::AccessToken.new("client", "openid email", subject: "account:1")
    probe = AuthorizationSecuritySpec::Probe.new("GET", "/oauth/userinfo")
    probe.context.request.headers["Authorization"] = "Bearer #{token.access_token}"
    Authly::UserInfoHandler.handle(probe.context)
    probe.status.should eq 200
    result = JSON.parse(probe.body)
    result["sub"].as_s.should eq "account:1"
    result["email_verified"].as_bool.should be_true
  end
end
