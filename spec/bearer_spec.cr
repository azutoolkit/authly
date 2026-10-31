require "./spec_helper"
require "./support/bearer_helpers"

describe Authly::Handler::Bearer do
  it "passes a valid token and exposes its claims downstream" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      response = BearerSpec.get(client, "/users", "Bearer #{BearerSpec.token}")

      response.status_code.should eq 200
      JSON.parse(response.body).should eq JSON.parse(%({"sub":"alice","scopes":["read:users","write:users"]}))
    end
  end

  it "protects every path except the ones listed" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      response = BearerSpec.get(client, "/public")
      response.status_code.should eq 200
      JSON.parse(response.body)["sub"].raw.should be_nil

      BearerSpec.get(client, "/public/deep/er").status_code.should eq 200
      BearerSpec.get(client, "/anything-else").status_code.should eq 401
    end
  end

  it "does not let a listed path cover a longer segment" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      BearerSpec.get(client, "/publicity").status_code.should eq 401
      BearerSpec.get(client, "/users/1").status_code.should eq 401
    end
  end

  it "keeps protecting after a request on a connection to a skipped path" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      BearerSpec.get(client, "/health").status_code.should eq 200
      BearerSpec.get(client, "/users").status_code.should eq 401
      BearerSpec.get(client, "/health").status_code.should eq 200
      BearerSpec.get(client, "/users", "Bearer #{BearerSpec.token}").status_code.should eq 200
      BearerSpec.get(client, "/users").status_code.should eq 401
    end
  end

  it "answers a request without credentials with a bare challenge" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      response = BearerSpec.get(client, "/users")

      response.status_code.should eq 401
      response.headers["WWW-Authenticate"].should eq %(Bearer realm="api")
    end
  end

  it "treats another scheme as no credentials" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      response = BearerSpec.get(client, "/users", "Basic dXNlcjpwYXNz")

      response.status_code.should eq 401
      response.headers["WWW-Authenticate"].should eq %(Bearer realm="api")
    end
  end

  it "rejects a malformed Authorization header with 400 invalid_request" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      ["Bearer", "Bearer ", "Bearer a b", "Bearer a\"b", "Bearer ===", "Bearertoken"].each do |header|
        response = BearerSpec.get(client, "/users", header)

        {header, response.status_code}.should eq({header, header == "Bearertoken" ? 401 : 400})
        response.headers["WWW-Authenticate"].should contain(header == "Bearertoken" ? %(Bearer realm="api") : %(error="invalid_request"))
      end
    end
  end

  it "rejects garbage, an oversized token and a tampered one with 401 invalid_token" do
    good = BearerSpec.token
    tampered = good.sub(/.$/) { |last| last == "A" ? "B" : "A" }
    BearerSpec.with_server(BearerSpec.chain) do |client|
      ["not.a.jwt", "x" * 9000, tampered, "a.b.c"].each do |bad|
        response = BearerSpec.get(client, "/users", "Bearer #{bad}")

        response.status_code.should eq 401
        response.headers["WWW-Authenticate"].should eq %(Bearer realm="api", error="invalid_token")
        response.body.should_not contain(bad)
      end
    end
  end

  it "rejects an expired token" do
    expired = BearerSpec.jwt(BearerSpec.payload({"exp" => 1.minute.ago.to_unix}))
    BearerSpec.with_server(BearerSpec.chain) do |client|
      BearerSpec.get(client, "/users", "Bearer #{expired}").status_code.should eq 401
    end
  end

  it "rejects a token that is not valid yet" do
    early = BearerSpec.jwt(BearerSpec.payload({"nbf" => 1.hour.from_now.to_unix}))
    BearerSpec.with_server(BearerSpec.chain) do |client|
      BearerSpec.get(client, "/users", "Bearer #{early}").status_code.should eq 401
    end
  end

  it "rejects a token signed with another key" do
    forged = BearerSpec.jwt(BearerSpec.payload, key: "another secret")
    BearerSpec.with_server(BearerSpec.chain) do |client|
      BearerSpec.get(client, "/users", "Bearer #{forged}").status_code.should eq 401
    end
  end

  it "rejects a token from another issuer" do
    foreign = BearerSpec.jwt(BearerSpec.payload({"iss" => "https://evil.example"}))
    BearerSpec.with_server(BearerSpec.chain) do |client|
      BearerSpec.get(client, "/users", "Bearer #{foreign}").status_code.should eq 401
    end
  end

  it "rejects a refresh token presented as an access token" do
    refresh = Authly::AccessToken.new("test_client", "read:users", subject: "alice").refresh_token.not_nil!
    BearerSpec.with_server(BearerSpec.chain) do |client|
      BearerSpec.get(client, "/users", "Bearer #{refresh}").status_code.should eq 401
    end
  end

  it "rejects a revoked token" do
    revoked = BearerSpec.token
    BearerSpec.with_server(BearerSpec.chain) do |client|
      BearerSpec.get(client, "/users", "Bearer #{revoked}").status_code.should eq 200
      Authly.revoke(revoked)
      BearerSpec.get(client, "/users", "Bearer #{revoked}").status_code.should eq 401
    end
  end

  it "accepts the scheme in any case and with extra spaces" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      token = BearerSpec.token
      ["bearer", "BEARER", "bEaReR"].each do |scheme|
        BearerSpec.get(client, "/users", "#{scheme} #{token}").status_code.should eq 200
      end
      BearerSpec.get(client, "/users", "Bearer   #{token}").status_code.should eq 200

      headers = HTTP::Headers{"aUtHoRiZaTiOn" => "Bearer #{token}"}
      client.get("/users", headers).status_code.should eq 200
    end
  end

  it "rejects two Authorization headers" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      headers = HTTP::Headers.new
      headers.add("Authorization", "Bearer #{BearerSpec.token}")
      headers.add("Authorization", "Bearer #{BearerSpec.token}")

      client.get("/users", headers).status_code.should eq 400
    end
  end

  describe "audience" do
    verifier = Authly::StrategyTokenVerifier.new(audience: "https://api.example.com")
    handlers = -> {
      [Authly::Handler::Bearer.new(verifier), ClaimsEcho.new] of HTTP::Handler
    }

    it "accepts a token for the audience, as a string or as one of several" do
      BearerSpec.with_server(handlers.call) do |client|
        single = BearerSpec.jwt(BearerSpec.payload({"aud" => "https://api.example.com"}))
        several = BearerSpec.jwt(BearerSpec.payload({"aud" => ["https://other", "https://api.example.com"]}))

        BearerSpec.get(client, "/", "Bearer #{single}").status_code.should eq 200
        BearerSpec.get(client, "/", "Bearer #{several}").status_code.should eq 200
      end
    end

    it "rejects another audience and a token without one" do
      BearerSpec.with_server(handlers.call) do |client|
        wrong = BearerSpec.jwt(BearerSpec.payload({"aud" => "https://other.example.com"}))
        none = BearerSpec.jwt(BearerSpec.payload)

        BearerSpec.get(client, "/", "Bearer #{wrong}").status_code.should eq 401
        BearerSpec.get(client, "/", "Bearer #{none}").status_code.should eq 401
      end
    end
  end

  describe "query string tokens" do
    it "are ignored by default" do
      BearerSpec.with_server(BearerSpec.chain) do |client|
        client.get("/users?access_token=#{BearerSpec.token}").status_code.should eq 401
      end
    end

    it "are read when enabled, but not next to a header" do
      handlers = [Authly::Handler::Bearer.new(allow_query_token: true), ClaimsEcho.new] of HTTP::Handler
      BearerSpec.with_server(handlers) do |client|
        token = BearerSpec.token

        client.get("/?access_token=#{token}").status_code.should eq 200
        client.get("/?access_token=bad").status_code.should eq 401
        BearerSpec.get(client, "/?access_token=#{token}", "Bearer #{token}").status_code.should eq 400
      end
    end
  end

  it "keeps the claims of concurrent requests apart" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      results = Channel(Tuple(String, String?)).new
      subjects = (1..12).map { |index| "user-#{index}" }

      subjects.each do |subject|
        token = BearerSpec.token("read:users", subject)
        spawn do
          own = HTTP::Client.new(client.host, client.port)
          body = BearerSpec.get(own, "/slow", "Bearer #{token}").body
          results.send({subject, JSON.parse(body)["sub"].as_s?})
        end
      end

      subjects.size.times do
        expected, seen = results.receive
        seen.should eq expected
      end
    end
  end

  it "does not let a client smuggle claims in through a header" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      headers = HTTP::Headers{"X-Authly-Claims" => %({"sub":"root"})}

      client.get("/slow", headers).status_code.should eq 401
    end
  end

  it "rejects an alg none token, while the same payload signed properly passes" do
    payload = BearerSpec.payload
    header = BearerSpec.b64(%({"alg":"none","typ":"JWT"}))
    unsigned = "#{header}.#{BearerSpec.b64(payload.to_json)}."
    signed = BearerSpec.jwt(payload)
    verifier = Authly::StrategyTokenVerifier.new

    verifier.verify(signed).should_not be_nil
    verifier.verify(unsigned).should be_nil
    verifier.verify(unsigned.chomp('.')).should be_nil
    verifier.verify("#{header}.#{BearerSpec.b64(payload.to_json)}.#{signed.rpartition('.').last}").should be_nil

    BearerSpec.with_server(BearerSpec.chain) do |client|
      BearerSpec.get(client, "/users", "Bearer #{unsigned}").status_code.should eq 401
    end
  end

  it "refuses a realm that could split the challenge" do
    expect_raises(ArgumentError) { Authly::Handler::Bearer.new(realm: %(a", error="none)) }
  end
end

describe Authly::Handler::RequireScope do
  it "refuses with 403 and names the required scope when one is missing" do
    token = BearerSpec.token("write:users")
    BearerSpec.with_server(BearerSpec.chain) do |client|
      response = BearerSpec.get(client, "/users", "Bearer #{token}")

      response.status_code.should eq 403
      response.headers["WWW-Authenticate"].should eq %(Bearer realm="api", error="insufficient_scope", scope="read:users")
    end
  end

  it "needs every scope of all-of" do
    handlers = [Authly::Handler::Bearer.new, Authly::Handler::RequireScope.all("a", "b"), ClaimsEcho.new] of HTTP::Handler
    BearerSpec.with_server(handlers) do |client|
      BearerSpec.get(client, "/", "Bearer #{BearerSpec.token("a")}").status_code.should eq 403
      BearerSpec.get(client, "/", "Bearer #{BearerSpec.token("b a c")}").status_code.should eq 200
    end
  end

  it "needs one scope of any-of, and lists them all in the challenge" do
    BearerSpec.with_server(BearerSpec.chain) do |client|
      denied = BearerSpec.get(client, "/admin", "Bearer #{BearerSpec.token("read:users")}")
      denied.status_code.should eq 403
      denied.headers["WWW-Authenticate"].should contain(%(scope="admin root"))

      BearerSpec.get(client, "/admin", "Bearer #{BearerSpec.token("root")}").status_code.should eq 200
    end
  end

  it "does not take a scope for a substring of another" do
    handlers = [Authly::Handler::Bearer.new, Authly::Handler::RequireScope.all("read"), ClaimsEcho.new] of HTTP::Handler
    BearerSpec.with_server(handlers) do |client|
      BearerSpec.get(client, "/", "Bearer #{BearerSpec.token("reader read:users")}").status_code.should eq 403
    end
  end

  it "refuses, rather than lets through, a request nothing authenticated" do
    handlers = [Authly::Handler::RequireScope.all("read"), ClaimsEcho.new] of HTTP::Handler
    BearerSpec.with_server(handlers) do |client|
      BearerSpec.get(client, "/").status_code.should eq 401
    end
  end

  it "refuses to be built without scopes or with unsafe ones" do
    expect_raises(ArgumentError) { Authly::Handler::RequireScope.new }
    expect_raises(ArgumentError) { Authly::Handler::RequireScope.all(%(a", error="x)) }
    expect_raises(ArgumentError) { Authly::Handler::RequireScope.all("two words") }
  end
end

describe "Bearer with opaque tokens" do
  it "verifies against the token store" do
    config = Authly.config
    previous = {config.token_strategy, config.token_store}
    config.token_strategy = :opaque
    config.token_store = Authly::InMemoryStore.new
    begin
      access = Authly::AccessToken.new("test_client", "read:users", subject: "bob")
      verifier = Authly::StrategyTokenVerifier.new

      claims = verifier.verify(access.access_token)
      claims.try(&.subject).should eq "bob"
      claims.try(&.scopes).should eq ["read:users"]
      verifier.verify(access.refresh_token.not_nil!).should be_nil
      verifier.verify("0" * 64).should be_nil
    ensure
      config.token_strategy, config.token_store = previous
    end
  end
end
