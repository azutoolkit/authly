require "./spec_helper"
require "./support/bearer_helpers"

class FailingStore
  include Authly::TokenStore

  property? failing = false

  def initialize(@store = Authly::InMemoryStore.new)
  end

  def store(token_id : String, payload)
    @store.store(token_id, payload)
  end

  def fetch(token_id : String)
    guard
    @store.fetch(token_id)
  end

  def revoke(token_id : String)
    @store.revoke(token_id)
  end

  def revoked?(token_id : String) : Bool
    guard
    @store.revoked?(token_id)
  end

  def valid?(token_id : String) : Bool
    !revoked?(token_id)
  end

  private def guard
    raise IO::Error.new("connection refused") if failing?
  end
end

module HardeningSpec
  extend self

  def with_config(&)
    config = Authly.config
    previous = {config.token_strategy, config.token_store, config.access_token_audience}
    begin
      yield config
    ensure
      config.token_strategy, config.token_store, config.access_token_audience = previous
    end
  end

  def server(bearer : Authly::Handler::Bearer, &)
    BearerSpec.with_server([bearer, ClaimsEcho.new] of HTTP::Handler) { |client| yield client }
  end
end

describe Authly::Handler::PathFilter do
  guarded = ->(filter : Authly::Handler::PathFilter, path : String) { filter.protects?(path) }

  describe "protecting everything but a list" do
    filter = Authly::Handler::PathFilter.new(except: ["/health", "/static/"])

    it "lets the listed paths and their subpaths through, however they are spelled" do
      ["/health", "/health/", "/health/live", "/static", "/static/app.css", "//health", "/./health", "/x/../health", "/%68ealth"].each do |path|
        {path, guarded.call(filter, path)}.should eq({path, false})
      end
    end

    it "protects everything else, including look-alikes and other cases" do
      ["/", "/healthz", "/HEALTH", "/api", "/health/../api", "/health/%2e%2e/api", "/health%2f..%2fapi", "/staticfiles"].each do |path|
        {path, guarded.call(filter, path)}.should eq({path, true})
      end
    end
  end

  describe "protecting an allowlist" do
    filter = Authly::Handler::PathFilter.new(prefixes: ["/api/"])

    it "protects the prefix however the path is spelled" do
      ["/api", "/api/", "/api/x/", "//api", "//api/x", "/API", "/Api/x", "/%61pi/x", "/x/../api/x", "/x/%2e%2e/api/x", "/api%2fx", "/api\\x"].each do |path|
        {path, guarded.call(filter, path)}.should eq({path, true})
      end
    end

    it "leaves the rest open" do
      ["/", "/apiary", "/other/api"].each do |path|
        {path, guarded.call(filter, path)}.should eq({path, false})
      end
    end

    it "applies except on top of the allowlist" do
      both = Authly::Handler::PathFilter.new(prefixes: ["/api"], except: ["/api/health"])

      both.protects?("/api/users").should be_true
      both.protects?("/api/health").should be_false
    end
  end

  it "refuses an allowlist that is empty" do
    expect_raises(ArgumentError) { Authly::Handler::PathFilter.new(prefixes: [] of String) }
  end
end

describe "Bearer path handling over the wire" do
  it "protects an allowlisted prefix however the request spells it" do
    handlers = [Authly::Handler::Bearer.new(prefixes: ["/api/"]), ClaimsEcho.new] of HTTP::Handler
    BearerSpec.with_server(handlers) do |client|
      ["/api", "/api/", "/API/x", "/%61pi/x", "/x/../api/x", "/x/%2e%2e/api/x"].each do |path|
        {path, BearerSpec.get(client, path).status_code}.should eq({path, 401})
      end
      BearerSpec.get(client, "/apiary").status_code.should eq 200
    end
  end

  it "applies RequireScope to the same spellings" do
    handlers = [Authly::Handler::Bearer.new, Authly::Handler::RequireScope.all("admin", prefixes: ["/admin"]), ClaimsEcho.new] of HTTP::Handler
    BearerSpec.with_server(handlers) do |client|
      token = BearerSpec.token("read:users")
      ["/admin", "/ADMIN/x", "/%61dmin", "/x/../admin"].each do |path|
        {path, BearerSpec.get(client, path, "Bearer #{token}").status_code}.should eq({path, 403})
      end
    end
  end
end

describe "context.authly_claims!" do
  it "raises a clear error when nothing authenticated the request" do
    context = HTTP::Server::Context.new(HTTP::Request.new("GET", "/"), HTTP::Server::Response.new(IO::Memory.new))

    expect_raises(Authly::MissingClaims, /Bearer has to run before/) { context.authly_claims! }
    context.authly_claims = Authly::Claims.from({"sub" => "alice"})
    context.authly_claims!.subject.should eq "alice"
  end
end

describe "token store failures" do
  it "answers 503 with Retry-After, not 401, while a JWT revocation store is down" do
    HardeningSpec.with_config do |config|
      store = FailingStore.new
      config.token_strategy = :jwt
      config.token_store = store
      token = BearerSpec.token

      HardeningSpec.server(Authly::Handler::Bearer.new) do |client|
        BearerSpec.get(client, "/", "Bearer #{token}").status_code.should eq 200

        store.failing = true
        response = BearerSpec.get(client, "/", "Bearer #{token}")
        response.status_code.should eq 503
        response.headers["Retry-After"].should eq "1"
        response.headers["Cache-Control"].should eq "no-store"
        response.headers["WWW-Authenticate"]?.should be_nil
        response.body.should_not contain(token)

        store.failing = false
        BearerSpec.get(client, "/", "Bearer #{token}").status_code.should eq 200
      end
    end
  end

  it "answers 503 while an opaque token store is down, and still refuses a token it does not know" do
    HardeningSpec.with_config do |config|
      store = FailingStore.new
      config.token_strategy = :opaque
      config.token_store = store
      token = BearerSpec.token

      HardeningSpec.server(Authly::Handler::Bearer.new) do |client|
        store.failing = true
        BearerSpec.get(client, "/", "Bearer #{token}").status_code.should eq 503

        store.failing = false
        BearerSpec.get(client, "/", "Bearer #{token}").status_code.should eq 200
        BearerSpec.get(client, "/", "Bearer #{"0" * 64}").status_code.should eq 401
      end
    end
  end

  it "lets the verifier raise instead of answering nil" do
    HardeningSpec.with_config do |config|
      store = FailingStore.new
      config.token_store = store
      token = BearerSpec.token
      store.failing = true

      expect_raises(Authly::VerificationUnavailable) { Authly::StrategyTokenVerifier.new.verify(token) }
    end
  end

  it "does not take a malformed token for a store failure" do
    HardeningSpec.with_config do |config|
      store = FailingStore.new
      config.token_store = store
      store.failing = true

      Authly::StrategyTokenVerifier.new.verify("not.a.jwt").should be_nil
      Authly::StrategyTokenVerifier.new.verify("a.b.%%%").should be_nil
    end
  end
end

describe "access token audience and type" do
  it "issues access tokens for the configured audience, base_url by default" do
    HardeningSpec.with_config do |config|
      claims = Authly::StrategyTokenVerifier.new.verify(BearerSpec.token).not_nil!
      claims["aud"].as_s.should eq config.base_url
      claims["token_type"].as_s.should eq "access_token"

      config.access_token_audience = "https://api.example.com"
      Authly::StrategyTokenVerifier.new.verify(BearerSpec.token).not_nil!["aud"].as_s.should eq "https://api.example.com"
    end
  end

  it "makes a verifier with an audience refuse tokens meant for another API" do
    HardeningSpec.with_config do |config|
      config.access_token_audience = "https://billing.example.com"
      for_billing = BearerSpec.token

      Authly::StrategyTokenVerifier.new(audience: "https://billing.example.com").verify(for_billing).should_not be_nil
      Authly::StrategyTokenVerifier.new(audience: "https://reports.example.com").verify(for_billing).should be_nil
    end
  end

  it "refuses refresh tokens, and tokens of another type, even with the legacy flag" do
    access = Authly::AccessToken.new("test_client", "read:users", subject: "alice")
    other = BearerSpec.jwt(BearerSpec.payload({"token_type" => "id_token"}))

    [Authly::StrategyTokenVerifier.new, Authly::StrategyTokenVerifier.new(legacy_tokens: true)].each do |verifier|
      verifier.verify(access.refresh_token).should be_nil
      verifier.verify(other).should be_nil
    end
  end

  it "accepts a token issued before token_type existed only with the legacy flag" do
    legacy = BearerSpec.jwt(BearerSpec.payload.reject("token_type"))

    Authly::StrategyTokenVerifier.new.verify(legacy).should be_nil
    Authly::StrategyTokenVerifier.new(legacy_tokens: true).verify(legacy).should_not be_nil
  end
end

describe Authly::StrategyTokenVerifier do
  it "uses the configuration it is given, not the global one" do
    own = Authly::Configuration.new
    own.secret_key = "another key entirely"
    own.issuer = "https://other-issuer.example"
    own.token_store = Authly::InMemoryStore.new
    verifier = Authly::StrategyTokenVerifier.new(own)

    payload = BearerSpec.payload({"iss" => own.issuer, "token_type" => "access_token"})
    token = JWT.encode(payload, own.secret_key, own.algorithm)
    verifier.verify(token).should_not be_nil
    verifier.verify(BearerSpec.token).should be_nil

    own.token_store.revoke(payload["jti"].to_s)
    verifier.verify(token).should be_nil
  end

  it "follows a token store replaced at runtime" do
    HardeningSpec.with_config do |config|
      config.token_strategy = :opaque
      config.token_store = Authly::InMemoryStore.new
      verifier = Authly::StrategyTokenVerifier.new

      first = BearerSpec.token
      verifier.verify(first).should_not be_nil

      config.token_store = Authly::InMemoryStore.new
      verifier.verify(first).should be_nil
      second = BearerSpec.token
      verifier.verify(second).should_not be_nil

      config.token_store.revoke(second)
      verifier.verify(second).should be_nil
    end
  end
end

describe "Bearer request edge cases" do
  it "does not take a tab for the separator after the scheme" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      BearerSpec.get(client, "/users", "Bearer\t#{BearerSpec.token}").status_code.should eq 401
      BearerSpec.get(client, "/users", "Bearer \t#{BearerSpec.token}").status_code.should eq 400
    end
  end

  it "treats HEAD like GET" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      client.head("/users").status_code.should eq 401
      client.head("/users", HTTP::Headers{"Authorization" => "Bearer #{BearerSpec.token}"}).status_code.should eq 200
    end
  end

  it "answers a CORS preflight with 401 unless told to let it through" do
    preflight = HTTP::Headers{"Origin" => "https://app.example", "Access-Control-Request-Method" => "GET"}
    BearerSpec.with_server(BearerSpec.chain) { |client| client.exec("OPTIONS", "/users", preflight).status_code.should eq 401 }

    HardeningSpec.server(Authly::Handler::Bearer.new(pass_preflight: true)) do |client|
      client.exec("OPTIONS", "/", preflight).status_code.should eq 200
      client.exec("OPTIONS", "/").status_code.should eq 401
      client.get("/", preflight).status_code.should eq 401
    end
  end

  it "needs any-of only when it is not empty" do
    handlers = [Authly::Handler::Bearer.new, Authly::Handler::RequireScope.new(all: ["a"], any: [] of String), ClaimsEcho.new] of HTTP::Handler
    BearerSpec.with_server(handlers) do |client|
      BearerSpec.get(client, "/", "Bearer #{BearerSpec.token("a")}").status_code.should eq 200
      BearerSpec.get(client, "/", "Bearer #{BearerSpec.token("b")}").status_code.should eq 403
    end
  end

  describe "query string tokens" do
    it "refuses a repeated access_token" do
      HardeningSpec.server(Authly::Handler::Bearer.new(allow_query_token: true)) do |client|
        token = BearerSpec.token
        client.get("/?access_token=#{token}&access_token=#{token}").status_code.should eq 400
      end
    end

    it "keeps the response out of caches and referrers, only when a query token was sent" do
      HardeningSpec.server(Authly::Handler::Bearer.new(allow_query_token: true)) do |client|
        response = client.get("/?access_token=#{BearerSpec.token}")
        response.headers["Cache-Control"].should eq "private"
        response.headers["Referrer-Policy"].should eq "no-referrer"

        header_only = BearerSpec.get(client, "/", "Bearer #{BearerSpec.token}")
        header_only.headers["Referrer-Policy"]?.should be_nil
      end
    end
  end
end
