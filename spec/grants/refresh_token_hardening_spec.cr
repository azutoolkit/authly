require "../spec_helper"

module RefreshSpec
  def self.refresh(token : String, client = "1", secret = "secret", scope : String? = nil) : Authly::AccessToken
    if scope
      Authly.access_token("refresh_token", client_id: client, client_secret: secret, refresh_token: token, scope: scope)
    else
      Authly.access_token("refresh_token", client_id: client, client_secret: secret, refresh_token: token)
    end
  end

  def self.rejected(code : Symbol = :invalid_grant, &)
    expect_raises(Authly::Error, Authly::ERROR_MSG[code]) { yield }
  end

  # Records the TTL a family revocation is stored with
  class TtlStore < Authly::InMemoryStore
    getter ttls = {} of String => Time::Span

    def revoke(token_id : String, ttl : Time::Span)
      @ttls[token_id] = ttl
      revoke(token_id)
    end
  end

  def self.claims(token : String) : Hash(String, JSON::Any)
    Authly.jwt_decode(token).first.as_h
  end

  def self.forged(claims : Hash(String, String | Int64)) : String
    Authly.jwt_encode({"iss" => Authly.config.issuer, "exp" => 1.hour.from_now.to_unix, "jti" => Random::Secure.hex(8)}.merge(claims))
  end
end

describe "Refresh token hardening" do
  describe "what is accepted as a refresh token" do
    it "refuses an access token" do
      issued = Authly::AccessToken.new("1", "read")
      RefreshSpec.rejected { RefreshSpec.refresh(issued.access_token) }
    end

    it "refuses an authorization code" do
      code = Authly::Code.new("1", "read", "https://www.example.com/callback", "", "", "john").jwt
      RefreshSpec.rejected { RefreshSpec.refresh(code) }
    end

    it "refuses a token that names no type" do
      RefreshSpec.rejected { RefreshSpec.refresh(RefreshSpec.forged({"sub" => "1", "cid" => "1"})) }
    end

    it "refuses an expired refresh token" do
      token = RefreshSpec.forged({"token_type" => "refresh_token", "sub" => "1", "cid" => "1", "scope" => "read", "fid" => "f", "exp" => 1.minute.ago.to_unix})
      RefreshSpec.rejected { RefreshSpec.refresh(token) }
    end

    it "refuses a revoked refresh token" do
      issued = Authly::AccessToken.new("1", "read")
      Authly.revoke(issued.refresh_token)
      RefreshSpec.rejected { RefreshSpec.refresh(issued.refresh_token) }
    end
  end

  describe "client binding" do
    it "refuses a refresh token issued to another client" do
      issued = Authly::AccessToken.new("1", "read")
      RefreshSpec.rejected { RefreshSpec.refresh(issued.refresh_token, client: "test_client", secret: "test_secret") }
    end

    it "does not consume the token when another client tried it" do
      issued = Authly::AccessToken.new("1", "read")
      RefreshSpec.rejected { RefreshSpec.refresh(issued.refresh_token, client: "test_client", secret: "test_secret") }
      RefreshSpec.refresh(issued.refresh_token).access_token.should_not be_empty
    end
  end

  describe "rotation" do
    it "answers with a new refresh token and takes the old one out of use" do
      first = Authly::AccessToken.new("1", "read write", subject: "john")
      second = RefreshSpec.refresh(first.refresh_token)

      second.refresh_token.should_not eq first.refresh_token
      RefreshSpec.rejected { RefreshSpec.refresh(first.refresh_token) }
    end

    it "lets the new refresh token be used in turn" do
      first = Authly::AccessToken.new("1", "read", subject: "john")
      third = RefreshSpec.refresh(RefreshSpec.refresh(first.refresh_token).refresh_token)
      third.access_token.should_not be_empty
    end

    it "redeems a refresh token once even when the store is asked twice" do
      issued = Authly::AccessToken.new("1", "read")
      jti = Authly.jwt_decode(issued.refresh_token).first["jti"].as_s
      results = Array.new(4) { Authly.config.token_store.consume(jti) }
      results.count(true).should eq 1
    end

    it "revokes the whole family when a consumed refresh token is presented again" do
      first = Authly::AccessToken.new("1", "read", subject: "john")
      second = RefreshSpec.refresh(first.refresh_token)

      RefreshSpec.rejected { RefreshSpec.refresh(first.refresh_token) }
      RefreshSpec.rejected { RefreshSpec.refresh(second.refresh_token) }
    end

    it "keeps the subject of the original grant" do
      first = Authly::AccessToken.new("1", "read", subject: "john")
      RefreshSpec.refresh(first.refresh_token).sub.should eq "john"
    end

    it "keeps other families alone" do
      mine = Authly::AccessToken.new("1", "read", subject: "john")
      other = Authly::AccessToken.new("1", "read", subject: "john")
      RefreshSpec.refresh(mine.refresh_token)
      RefreshSpec.rejected { RefreshSpec.refresh(mine.refresh_token) }
      RefreshSpec.refresh(other.refresh_token).access_token.should_not be_empty
    end
  end

  describe "scope" do
    it "carries the original scope into the refreshed token" do
      first = Authly::AccessToken.new("1", "read write", subject: "john")
      RefreshSpec.refresh(first.refresh_token).scope.should eq "read write"
    end

    it "keeps the original scope through every rotation" do
      first = Authly::AccessToken.new("1", "read write", subject: "john")
      second = RefreshSpec.refresh(first.refresh_token, scope: "read")
      second.scope.should eq "read"
      RefreshSpec.refresh(second.refresh_token).scope.should eq "read write"
    end

    it "narrows the scope on request" do
      first = Authly::AccessToken.new("1", "read write", subject: "john")
      RefreshSpec.refresh(first.refresh_token, scope: "write").scope.should eq "write"
    end

    it "refuses a scope the original grant did not have" do
      first = Authly::AccessToken.new("1", "read", subject: "john")
      RefreshSpec.rejected(:invalid_scope) { RefreshSpec.refresh(first.refresh_token, scope: "read admin") }
    end

    it "does not consume the token when the scope is refused" do
      first = Authly::AccessToken.new("1", "read", subject: "john")
      RefreshSpec.rejected(:invalid_scope) { RefreshSpec.refresh(first.refresh_token, scope: "admin") }
      RefreshSpec.refresh(first.refresh_token).scope.should eq "read"
    end
  end

  describe "absolute lifetime" do
    it "stamps a new family with its end and never lets a token outlive it" do
      first = Authly::AccessToken.new("1", "read", subject: "john")
      claims = RefreshSpec.claims(first.refresh_token)
      claims["fexp"].as_i64.should be_close((Time.utc + Authly.config.refresh_absolute_ttl).to_unix, 5)
      claims["exp"].as_i64.should be <= claims["fexp"].as_i64
    end

    it "carries the end of the family through every rotation" do
      first = Authly::AccessToken.new("1", "read", subject: "john")
      second = RefreshSpec.refresh(first.refresh_token)
      RefreshSpec.claims(second.refresh_token)["fexp"].should eq RefreshSpec.claims(first.refresh_token)["fexp"]
    end

    it "keeps the end of the family when the setting changes in between" do
      previous = Authly.config.refresh_absolute_ttl
      Authly.config.refresh_absolute_ttl = 10.days
      first = Authly::AccessToken.new("1", "read", subject: "john")
      Authly.config.refresh_absolute_ttl = 20.days
      begin
        second = RefreshSpec.refresh(first.refresh_token)
        third = RefreshSpec.refresh(second.refresh_token)
        fexp = RefreshSpec.claims(first.refresh_token)["fexp"]
        RefreshSpec.claims(second.refresh_token)["fexp"].should eq fexp
        RefreshSpec.claims(third.refresh_token)["fexp"].should eq fexp
      ensure
        Authly.config.refresh_absolute_ttl = previous
      end
    end

    it "caps the lifetime of a token at the end of its family" do
      previous = Authly.config.refresh_absolute_ttl
      Authly.config.refresh_absolute_ttl = 30.minutes
      begin
        claims = RefreshSpec.claims(Authly::AccessToken.new("1", "read", subject: "john").refresh_token)
        claims["exp"].as_i64.should eq claims["fexp"].as_i64
      ensure
        Authly.config.refresh_absolute_ttl = previous
      end
    end

    it "refuses a token whose family has ended, however fresh the token is" do
      token = RefreshSpec.forged({"token_type" => "refresh_token", "sub" => "john", "cid" => "1", "scope" => "read", "fid" => "ended",
                                  "iat" => Time.utc.to_unix, "fexp" => 1.minute.ago.to_unix})
      RefreshSpec.rejected { RefreshSpec.refresh(token) }
    end

    it "counts a token without fexp from its own issue time" do
      stale = RefreshSpec.forged({"token_type" => "refresh_token", "sub" => "john", "cid" => "1", "scope" => "read", "fid" => "old",
                                  "iat" => (Time.utc - Authly.config.refresh_absolute_ttl - 1.day).to_unix})
      RefreshSpec.rejected { RefreshSpec.refresh(stale) }

      recent = RefreshSpec.forged({"token_type" => "refresh_token", "sub" => "john", "cid" => "1", "scope" => "read", "fid" => "recent",
                                   "iat" => Time.utc.to_unix})
      RefreshSpec.claims(RefreshSpec.refresh(recent).refresh_token)["fexp"]?.should_not be_nil
    end
  end

  describe "revoking a refresh token" do
    it "revokes its whole family" do
      first = Authly::AccessToken.new("1", "read", subject: "john")
      second = RefreshSpec.refresh(first.refresh_token)

      Authly.revoke(first.refresh_token)
      RefreshSpec.rejected { RefreshSpec.refresh(second.refresh_token) }
    end

    it "keeps other families alone" do
      mine = Authly::AccessToken.new("1", "read", subject: "john")
      other = Authly::AccessToken.new("1", "read", subject: "john")
      Authly.revoke(mine.refresh_token)
      RefreshSpec.refresh(other.refresh_token).access_token.should_not be_empty
    end

    it "does not touch a family when an access token is revoked" do
      issued = Authly::AccessToken.new("1", "read", subject: "john")
      Authly.revoke(issued.access_token)
      RefreshSpec.refresh(issued.refresh_token).access_token.should_not be_empty
    end

    it "stores the family revocation for refresh_ttl in a store that takes a TTL" do
      previous = Authly.config.token_store
      store = RefreshSpec::TtlStore.new
      Authly.config.token_store = store
      begin
        issued = Authly::AccessToken.new("1", "read", subject: "john")
        family = RefreshSpec.claims(issued.refresh_token)["fid"].as_s
        Authly.revoke(issued.refresh_token)
        store.ttls["refresh-family:#{family}"].should eq Authly.config.refresh_ttl
      ensure
        Authly.config.token_store = previous
      end
    end

    it "gives the family revocation of a replayed token the same TTL" do
      previous = Authly.config.token_store
      store = RefreshSpec::TtlStore.new
      Authly.config.token_store = store
      begin
        first = Authly::AccessToken.new("1", "read", subject: "john")
        RefreshSpec.refresh(first.refresh_token)
        RefreshSpec.rejected { RefreshSpec.refresh(first.refresh_token) }
        store.ttls.values.should eq [Authly.config.refresh_ttl]
      ensure
        Authly.config.token_store = previous
      end
    end
  end

  describe "the scopes the client may have now" do
    it "refuses a refresh whose scope the client no longer holds, without consuming the token" do
      Authly.clients << Authly::Client.new("shrunk", "secret", "https://www.example.com/callback", "shrunk", "read", "authorization_code refresh_token")
      token = RefreshSpec.forged({"token_type" => "refresh_token", "sub" => "john", "cid" => "shrunk", "scope" => "read write", "fid" => "shrunk-family",
                                  "iat" => Time.utc.to_unix, "fexp" => 1.day.from_now.to_unix, "jti" => "shrunk-jti"})

      RefreshSpec.rejected(:invalid_scope) { RefreshSpec.refresh(token, client: "shrunk") }
      Authly.config.token_store.revoked?("shrunk-jti").should be_false
      RefreshSpec.refresh(token, client: "shrunk", scope: "read").scope.should eq "read"
    end
  end

  describe "as an access token" do
    it "is refused by the userinfo endpoint" do
      refresh = Authly::AccessToken.new("test_client", "openid profile", subject: "john").refresh_token
      io = IO::Memory.new
      response = HTTP::Server::Response.new(io)
      headers = HTTP::Headers{"Authorization" => "Bearer #{refresh}"}
      Authly::UserInfoHandler.handle(HTTP::Server::Context.new(HTTP::Request.new("GET", "/oauth/userinfo", headers), response))
      response.close
      io.rewind
      io.gets_to_end.should start_with("HTTP/1.1 401")
    end
  end
end
