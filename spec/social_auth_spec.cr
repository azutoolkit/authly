require "./spec_helper"

private class MockSocialHttpClient
  include Authly::Social::HttpClient

  property post_responses = Hash(String, Authly::Social::HttpResponse).new
  property get_responses = Hash(String, Authly::Social::HttpResponse).new
  property last_post_params = Hash(String, String).new

  def post_form(
    url : String,
    params : Hash(String, String),
    headers : HTTP::Headers = HTTP::Headers.new,
  ) : Authly::Social::HttpResponse
    @last_post_params = params
    @post_responses[url]? || Authly::Social::HttpResponse.new(404, %({"error":"not_found"}))
  end

  def get(
    url : String,
    headers : HTTP::Headers = HTTP::Headers.new,
  ) : Authly::Social::HttpResponse
    @get_responses[url]? || Authly::Social::HttpResponse.new(404, %({"error":"not_found"}))
  end
end

private def reset_social_test_config!(mock_http : MockSocialHttpClient)
  Authly.config.social_providers.clear
  Authly.config.social_owner_resolver = nil
  Authly.config.on_social_authenticated = nil
  Authly.config.social_http_client = mock_http
  Authly.config.state_store = Authly::InMemoryStateStore.new
end

describe "Social Sign-In Authentication" do
  describe "Built-in Social Providers" do
    it "exchanges code and builds profile for Google" do
      mock_http = MockSocialHttpClient.new
      reset_social_test_config!(mock_http)

      mock_http.post_responses[Authly::Social::Google::TOKEN_URL] = Authly::Social::HttpResponse.new(
        200,
        {
          access_token:  "goog-access-123",
          refresh_token: "goog-refresh-123",
          expires_in:    3600,
        }.to_json
      )
      mock_http.get_responses[Authly::Social::Google::USERINFO_URL] = Authly::Social::HttpResponse.new(
        200,
        {
          sub:            "google-uid-999",
          email:          "alice@example.com",
          email_verified: true,
          name:           "Alice Smith",
          given_name:     "Alice",
          family_name:    "Smith",
          picture:        "https://example.com/alice.png",
        }.to_json
      )

      provider = Authly::Social::Google.new(
        client_id: "goog-client",
        client_secret: "goog-secret",
        redirect_uri: "http://localhost:8080/oauth/social/google/callback"
      )

      auth_url = provider.authorize_url(state: "state-1", code_challenge: "challenge-1")
      auth_url.should contain("https://accounts.google.com/o/oauth2/v2/auth")
      auth_url.should contain("code_challenge=challenge-1")
      auth_url.should contain("code_challenge_method=S256")

      profile = provider.exchange_code("goog-code", code_verifier: "verifier-1")
      mock_http.last_post_params["code_verifier"]?.should eq("verifier-1")
      profile.provider.should eq("google")
      profile.uid.should eq("google-uid-999")
      profile.email.should eq("alice@example.com")
      profile.email_verified?.should be_true
      profile.name.should eq("Alice Smith")
      profile.first_name.should eq("Alice")
      profile.last_name.should eq("Smith")
      profile.avatar_url.should eq("https://example.com/alice.png")
    end

    it "exchanges code and fetches primary verified email from /user/emails for GitHub" do
      mock_http = MockSocialHttpClient.new
      reset_social_test_config!(mock_http)

      mock_http.post_responses[Authly::Social::GitHub::TOKEN_URL] = Authly::Social::HttpResponse.new(
        200,
        {access_token: "gh-access-123"}.to_json
      )
      mock_http.get_responses[Authly::Social::GitHub::USERINFO_URL] = Authly::Social::HttpResponse.new(
        200,
        {
          id:         424242,
          login:      "octocat",
          name:       "Mona Octocat",
          email:      nil,
          avatar_url: "https://avatars.githubusercontent.com/u/424242",
        }.to_json
      )
      mock_http.get_responses[Authly::Social::GitHub::EMAILS_URL] = Authly::Social::HttpResponse.new(
        200,
        [
          {email: "secondary@example.com", primary: false, verified: true},
          {email: "mona@github.com", primary: true, verified: true},
        ].to_json
      )

      provider = Authly::Social::GitHub.new(
        client_id: "gh-client",
        client_secret: "gh-secret",
        redirect_uri: "http://localhost:8080/oauth/social/github/callback"
      )

      profile = provider.exchange_code("gh-code")
      profile.provider.should eq("github")
      profile.uid.should eq("424242")
      profile.nickname.should eq("octocat")
      profile.name.should eq("Mona Octocat")
      profile.email.should eq("mona@github.com")
      profile.email_verified?.should be_true
    end

    it "verifies id_token and merges first-login user JSON for Apple" do
      mock_http = MockSocialHttpClient.new
      reset_social_test_config!(mock_http)

      apple_id_token = JWT.encode(
        {
          "iss"            => "https://appleid.apple.com",
          "aud"            => "com.example.app",
          "sub"            => "apple-user-001",
          "email"          => "appleuser@privaterelay.appleid.com",
          "email_verified" => "true",
          "exp"            => (Time.utc + 10.minutes).to_unix,
        },
        "apple-test-secret",
        JWT::Algorithm::HS256
      )

      mock_http.post_responses[Authly::Social::Apple::TOKEN_URL] = Authly::Social::HttpResponse.new(
        200,
        {
          access_token: "apple-access-123",
          id_token:     apple_id_token,
          expires_in:   3600,
        }.to_json
      )

      provider = Authly::Social::Apple.new(
        client_id: "com.example.app",
        client_secret: "apple-client-secret",
        redirect_uri: "https://example.com/oauth/social/apple/callback"
      )

      auth_url = provider.authorize_url(state: "st-apple")
      auth_url.should contain("response_mode=form_post")

      user_json = {name: {firstName: "Jane", lastName: "Appleseed"}}.to_json
      profile = provider.exchange_code("apple-code", extra_params: {"user" => user_json})
      profile.provider.should eq("apple")
      profile.uid.should eq("apple-user-001")
      profile.email.should eq("appleuser@privaterelay.appleid.com")
      profile.email_verified?.should be_true
      profile.first_name.should eq("Jane")
      profile.last_name.should eq("Appleseed")
      profile.name.should eq("Jane Appleseed")
    end

    it "exchanges code and builds profile for Microsoft Entra ID and Discord and GenericOAuth2" do
      mock_http = MockSocialHttpClient.new
      reset_social_test_config!(mock_http)

      ms = Authly::Social::Microsoft.new(
        client_id: "ms-client",
        client_secret: "ms-secret",
        redirect_uri: "http://localhost:8080/oauth/social/microsoft/callback",
        tenant: "contoso.onmicrosoft.com"
      )
      ms.authorize_endpoint.should eq("https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize")
      mock_http.post_responses[ms.token_endpoint] = Authly::Social::HttpResponse.new(
        200,
        {access_token: "ms-access-token"}.to_json
      )
      mock_http.get_responses[Authly::Social::Microsoft::USERINFO_URL] = Authly::Social::HttpResponse.new(
        200,
        {
          sub:                "ms-uid-77",
          preferred_username: "bob@contoso.com",
          name:               "Bob Contoso",
        }.to_json
      )

      ms_profile = ms.exchange_code("ms-code")
      ms_profile.uid.should eq("ms-uid-77")
      ms_profile.email.should eq("bob@contoso.com")
      ms_profile.email_verified?.should be_true

      discord = Authly::Social::Discord.new(
        client_id: "disc-client",
        client_secret: "disc-secret",
        redirect_uri: "http://localhost:8080/oauth/social/discord/callback"
      )
      mock_http.post_responses[Authly::Social::Discord::TOKEN_URL] = Authly::Social::HttpResponse.new(
        200,
        {access_token: "disc-access-token"}.to_json
      )
      mock_http.get_responses[Authly::Social::Discord::USERINFO_URL] = Authly::Social::HttpResponse.new(
        200,
        {
          id:          "80351110224678912",
          username:    "nelly",
          global_name: "Nelly",
          avatar:      "8342729096ea3675442027381ff50dfe",
          email:       "nelly@discord.com",
          verified:    true,
        }.to_json
      )

      disc_profile = discord.exchange_code("disc-code")
      disc_profile.uid.should eq("80351110224678912")
      disc_profile.avatar_url.should eq("https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe.png")

      generic = Authly::Social::GenericOAuth2.new(
        name: "gitlab",
        client_id: "gl-client",
        client_secret: "gl-secret",
        redirect_uri: "http://localhost:8080/oauth/social/gitlab/callback",
        authorize_endpoint: "https://gitlab.example.com/oauth/authorize",
        token_endpoint: "https://gitlab.example.com/oauth/token",
        userinfo_endpoint: "https://gitlab.example.com/oauth/userinfo"
      )
      mock_http.post_responses[generic.token_endpoint] = Authly::Social::HttpResponse.new(
        200,
        {access_token: "gl-access"}.to_json
      )
      mock_http.get_responses[generic.userinfo_endpoint] = Authly::Social::HttpResponse.new(
        200,
        {
          sub:            "gl-101",
          email:          "dev@gitlab.example.com",
          email_verified: true,
          name:           "GitLab Dev",
        }.to_json
      )

      gl_profile = generic.exchange_code("gl-code")
      gl_profile.provider.should eq("gitlab")
      gl_profile.uid.should eq("gl-101")
      gl_profile.email.should eq("dev@gitlab.example.com")
    end
  end

  describe "HTTP Redirect & Callback Flow (/oauth/social/:provider)" do
    it "initiates redirect, verifies callback state once, resolves owner, and prevents state replay" do
      mock_http = MockSocialHttpClient.new
      reset_social_test_config!(mock_http)

      google = Authly::Social::Google.new(
        client_id: "goog-client",
        client_secret: "goog-secret",
        redirect_uri: "http://localhost:8080/oauth/social/google/callback"
      )
      Authly.config.register_social_provider(google)

      Authly.owners << Authly::Owner.new(
        username: "social_alice",
        password: "unused-password",
        id: "owner-social-alice",
        email: "alice@example.com",
        social_identities: {"google" => "google-uid-999"}
      )

      mock_http.post_responses[Authly::Social::Google::TOKEN_URL] = Authly::Social::HttpResponse.new(
        200,
        {access_token: "goog-access-123"}.to_json
      )
      mock_http.get_responses[Authly::Social::Google::USERINFO_URL] = Authly::Social::HttpResponse.new(
        200,
        {
          sub:            "google-uid-999",
          email:          "alice@example.com",
          email_verified: true,
          name:           "Alice Smith",
        }.to_json
      )

      handler = Authly::Handler.new

      # Step 1: GET /oauth/social/google
      start_req = HTTP::Request.new("GET", "/oauth/social/google?scope=read+openid")
      start_io = IO::Memory.new
      start_ctx = HTTP::Server::Context.new(start_req, HTTP::Server::Response.new(start_io))
      handler.call(start_ctx)
      start_ctx.response.close
      start_io.rewind
      start_res = HTTP::Client::Response.from_io(start_io)

      start_res.status_code.should eq(302)
      location = URI.parse(start_res.headers["Location"])
      location.host.should eq("accounts.google.com")
      query_params = URI::Params.parse(location.query || "")
      state = query_params["state"]
      query_params["code_challenge_method"].should eq("S256")
      query_params["code_challenge"].should_not be_empty

      # Step 2: GET /oauth/social/google/callback
      cb_req = HTTP::Request.new("GET", "/oauth/social/google/callback?code=goog-auth-code&state=#{URI.encode_www_form(state)}")
      cb_io = IO::Memory.new
      cb_ctx = HTTP::Server::Context.new(cb_req, HTTP::Server::Response.new(cb_io))
      handler.call(cb_ctx)
      cb_ctx.response.close
      cb_io.rewind
      cb_res = HTTP::Client::Response.from_io(cb_io)

      cb_res.status_code.should eq(200)
      body = JSON.parse(cb_res.body)
      body["sub"].as_s.should eq("owner-social-alice")
      body["provider"].as_s.should eq("google")
      body["social_uid"].as_s.should eq("google-uid-999")
      body["access_token"].as_s.should_not be_empty
      body["id_token"].as_s.should_not be_empty

      # Step 3: Replay with the same state token must fail (nonce consumed)
      replay_req = HTTP::Request.new("GET", "/oauth/social/google/callback?code=goog-auth-code&state=#{URI.encode_www_form(state)}")
      replay_io = IO::Memory.new
      replay_ctx = HTTP::Server::Context.new(replay_req, HTTP::Server::Response.new(replay_io))
      handler.call(replay_ctx)
      replay_ctx.response.close
      replay_io.rewind
      replay_res = HTTP::Client::Response.from_io(replay_io)

      replay_res.status_code.should eq(400)
      JSON.parse(replay_res.body)["error"].as_s.should eq("invalid_state")
    end

    it "redirects back to OAuth client redirect_uri with an Authly authorization code when client_id is provided" do
      mock_http = MockSocialHttpClient.new
      reset_social_test_config!(mock_http)

      github = Authly::Social::GitHub.new(
        client_id: "gh-client",
        client_secret: "gh-secret",
        redirect_uri: "http://localhost:8080/oauth/social/github/callback",
        scopes: ["read:user"]
      )
      Authly.config.register_social_provider(github)
      Authly.config.social_owner_resolver = ->(profile : Authly::SocialProfile) : String? {
        "gh-user-#{profile.uid}"
      }

      mock_http.post_responses[Authly::Social::GitHub::TOKEN_URL] = Authly::Social::HttpResponse.new(
        200,
        {access_token: "gh-token-abc"}.to_json
      )
      mock_http.get_responses[Authly::Social::GitHub::USERINFO_URL] = Authly::Social::HttpResponse.new(
        200,
        {id: 777, login: "crystaldev"}.to_json
      )

      handler = Authly::Handler.new

      start_req = HTTP::Request.new(
        "GET",
        "/oauth/social/github?client_id=1&redirect_uri=#{URI.encode_www_form("https://www.example.com/callback")}&scope=read&state=client-xyz"
      )
      start_io = IO::Memory.new
      start_ctx = HTTP::Server::Context.new(start_req, HTTP::Server::Response.new(start_io))
      handler.call(start_ctx)
      start_ctx.response.close
      start_io.rewind
      start_res = HTTP::Client::Response.from_io(start_io)

      start_res.status_code.should eq(302)
      state = URI::Params.parse(URI.parse(start_res.headers["Location"]).query || "")["state"]

      cb_req = HTTP::Request.new("GET", "/oauth/social/github/callback?code=gh-code-1&state=#{URI.encode_www_form(state)}")
      cb_io = IO::Memory.new
      cb_ctx = HTTP::Server::Context.new(cb_req, HTTP::Server::Response.new(cb_io))
      handler.call(cb_ctx)
      cb_ctx.response.close
      cb_io.rewind
      cb_res = HTTP::Client::Response.from_io(cb_io)

      cb_res.status_code.should eq(302)
      cb_location = URI.parse(cb_res.headers["Location"])
      cb_params = URI::Params.parse(cb_location.query || "")
      cb_params["state"].should eq("client-xyz")
      authly_code = cb_params["code"]
      authly_code.should_not be_empty

      # Exchange the issued Authly authorization code at POST /oauth/token
      token = Authly.access_token(
        "authorization_code",
        client_id: "1",
        client_secret: "secret",
        redirect_uri: "https://www.example.com/callback",
        code: authly_code
      )
      token.sub.should eq("gh-user-777")
    end
  end

  describe "Token Endpoint Social Grant (POST /oauth/token)" do
    it "exchanges social code or subject_token via grant_type=social and urn:ietf:params:oauth:grant-type:social" do
      mock_http = MockSocialHttpClient.new
      reset_social_test_config!(mock_http)

      google = Authly::Social::Google.new(
        client_id: "goog-client",
        client_secret: "goog-secret",
        redirect_uri: "http://localhost:8080/oauth/social/google/callback"
      )
      Authly.config.register_social_provider(google)
      Authly.config.social_owner_resolver = ->(profile : Authly::SocialProfile) : String? {
        "resolved-#{profile.provider}-#{profile.uid}"
      }

      mock_http.post_responses[Authly::Social::Google::TOKEN_URL] = Authly::Social::HttpResponse.new(
        200,
        {access_token: "goog-token-99"}.to_json
      )
      mock_http.get_responses[Authly::Social::Google::USERINFO_URL] = Authly::Social::HttpResponse.new(
        200,
        {
          sub:            "987654",
          email:          "user@example.com",
          email_verified: true,
        }.to_json
      )

      handler = Authly::Handler.new

      # 1. Exchange via code with grant_type=social
      body = URI::Params.encode({
        "grant_type"    => "social",
        "client_id"     => "1",
        "client_secret" => "secret",
        "provider"      => "google",
        "code"          => "upstream-google-code",
        "scope"         => "read openid",
      })
      req = HTTP::Request.new(
        "POST",
        "/oauth/token",
        headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
        body: body
      )
      io = IO::Memory.new
      ctx = HTTP::Server::Context.new(req, HTTP::Server::Response.new(io))
      handler.call(ctx)
      ctx.response.close
      io.rewind
      res = HTTP::Client::Response.from_io(io)

      res.status_code.should eq(200)
      token_json = JSON.parse(res.body)
      token_json["sub"].as_s.should eq("resolved-google-987654")
      token_json["access_token"].as_s.should_not be_empty
      token_json["id_token"].as_s.should_not be_empty

      # 2. Exchange via subject_token with urn:ietf:params:oauth:grant-type:social
      body2 = URI::Params.encode({
        "grant_type"    => "urn:ietf:params:oauth:grant-type:social",
        "client_id"     => "1",
        "provider"      => "google",
        "subject_token" => "goog-token-99",
        "scope"         => "read",
      })
      req2 = HTTP::Request.new(
        "POST",
        "/oauth/token",
        headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
        body: body2
      )
      io2 = IO::Memory.new
      ctx2 = HTTP::Server::Context.new(req2, HTTP::Server::Response.new(io2))
      handler.call(ctx2)
      ctx2.response.close
      io2.rewind
      res2 = HTTP::Client::Response.from_io(io2)

      res2.status_code.should eq(200)
      JSON.parse(res2.body)["sub"].as_s.should eq("resolved-google-987654")
    end

    it "returns access_denied when social_owner_resolver returns nil" do
      mock_http = MockSocialHttpClient.new
      reset_social_test_config!(mock_http)

      google = Authly::Social::Google.new(
        client_id: "goog-client",
        client_secret: "goog-secret",
        redirect_uri: "http://localhost:8080/oauth/social/google/callback"
      )
      Authly.config.register_social_provider(google)
      Authly.config.social_owner_resolver = ->(_profile : Authly::SocialProfile) : String? { nil }

      mock_http.get_responses[Authly::Social::Google::USERINFO_URL] = Authly::Social::HttpResponse.new(
        200,
        {sub: "unmapped-uid-000", email: "nobody@example.com", email_verified: false}.to_json
      )

      expect_raises(Authly::Error, "The user or authorization server denied the request") do
        Authly.access_token(
          "social",
          client_id: "1",
          client_secret: "secret",
          provider: "google",
          subject_token: "some-upstream-token"
        )
      end
    end
  end
end
