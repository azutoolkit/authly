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
