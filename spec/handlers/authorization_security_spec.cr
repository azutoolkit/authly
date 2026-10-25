require "../spec_helper"

# Security regression specs for the authorization endpoint and the device page:
# no authentication from request parameters, consent only by a signed POST, escaped HTML.
describe "Authorization endpoint security" do
  describe "fail closed without an authentication hook" do
    it "refuses the old query-string bypass and issues no code" do
      AuthorizationSecuritySpec.without_hook do
        probe = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params + "&consent=approved&user_id=admin")
        probe.status.should eq 500
        probe.location.should be_nil
        probe.body.should contain("authenticate_user")
        probe.body.should_not contain("code=")
      end
    end

    it "refuses a plain request too and a POST" do
      AuthorizationSecuritySpec.without_hook do
        AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params).status.should eq 500
        probe = AuthorizationSecuritySpec.decide({"consent_token" => "x", "decision" => "approve", "user_id" => "admin"})
        probe.status.should eq 500
        probe.location.should be_nil
      end
    end

    it "refuses the implicit flow" do
      AuthorizationSecuritySpec.without_hook do
        probe = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params(response_type: "token", scope: "admin") + "&consent=approved")
        probe.status.should eq 500
        probe.location.should be_nil
      end
    end
  end

  describe "authentication" do
    it "answers 401 login_required when nobody is signed in" do
      AuthorizationSecuritySpec.with_hook do
        probe = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params + "&consent=approved&user_id=admin")
        probe.status.should eq 401
        probe.location.should be_nil
        probe.body.should contain("login_required")
      end
    end

    it "redirects to the configured login page" do
      AuthorizationSecuritySpec.with_hook do
        Authly.config.login_url = ->(ctx : HTTP::Server::Context) { "/login?return_to=#{URI.encode_www_form(ctx.request.resource)}" }
        probe = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params)
        probe.status.should eq 302
        probe.location.not_nil!.should start_with("/login?return_to=")
      end
    end

    it "ignores user_id and consent in the query: a signed-in user still gets the consent page, never a code" do
      AuthorizationSecuritySpec.with_hook do
        probe = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params + "&consent=approved&user_id=admin", user: "john")
        probe.status.should eq 200
        probe.location.should be_nil
        probe.body.should contain("consent_token")
        probe.body.should_not contain("admin")
      end
    end
  end

  describe "consent" do
    it "issues a code for the authenticated subject after a signed POST" do
      AuthorizationSecuritySpec.with_hook do
        page = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params, user: "john")
        probe = AuthorizationSecuritySpec.decide({"consent_token" => page.consent_token, "decision" => "approve", "user_id" => "admin"}, user: "john")
        probe.status.should eq 302
        location = probe.location.not_nil!
        location.should start_with(AuthorizationSecuritySpec::CALLBACK)
        location.should contain("state=st-1")
        AuthorizationSecuritySpec.code_subject(location).should eq "john"
      end
    end

    it "rejects a POST without a token" do
      AuthorizationSecuritySpec.with_hook do
        probe = AuthorizationSecuritySpec.decide({"decision" => "approve", "client_id" => "1", "redirect_uri" => AuthorizationSecuritySpec::CALLBACK}, user: "john")
        probe.status.should eq 400
        probe.location.should be_nil
      end
    end

    it "rejects a tampered or foreign token" do
      AuthorizationSecuritySpec.with_hook do
        page = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params, user: "john")
        token = page.consent_token
        tampered = token.sub(/.$/) { |c| c == "0" ? "1" : "0" }
        AuthorizationSecuritySpec.decide({"consent_token" => tampered, "decision" => "approve"}, user: "john").location.should be_nil
        AuthorizationSecuritySpec.decide({"consent_token" => "garbage", "decision" => "approve"}, user: "john").status.should eq 400
        forged = Authly::FormToken.issue("something-else", {"subject" => "admin"}, 5.minutes)
        AuthorizationSecuritySpec.decide({"consent_token" => forged, "decision" => "approve"}, user: "admin").location.should be_nil
      end
    end

    it "rejects a token issued to another subject (CSRF with the attacker's own token)" do
      AuthorizationSecuritySpec.with_hook do
        attackers_page = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params, user: "mallory")
        probe = AuthorizationSecuritySpec.decide({"consent_token" => attackers_page.consent_token, "decision" => "approve"}, user: "victim")
        probe.status.should eq 403
        probe.location.should be_nil
      end
    end

    it "rejects a POST when nobody is signed in" do
      AuthorizationSecuritySpec.with_hook do
        page = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params, user: "john")
        probe = AuthorizationSecuritySpec.decide({"consent_token" => page.consent_token, "decision" => "approve"})
        probe.status.should eq 401
        probe.location.should be_nil
      end
    end

    it "accepts a consent token once" do
      AuthorizationSecuritySpec.with_hook do
        page = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params, user: "john")
        form = {"consent_token" => page.consent_token, "decision" => "approve"}
        AuthorizationSecuritySpec.decide(form, user: "john").status.should eq 302
        replay = AuthorizationSecuritySpec.decide(form, user: "john")
        replay.status.should eq 400
        replay.location.should be_nil
      end
    end

    it "answers access_denied on deny" do
      AuthorizationSecuritySpec.with_hook do
        page = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params, user: "john")
        probe = AuthorizationSecuritySpec.decide({"consent_token" => page.consent_token, "decision" => "deny"}, user: "john")
        probe.status.should eq 302
        probe.location.not_nil!.should contain("error=access_denied")
        probe.location.not_nil!.should contain("state=st-1")
        probe.location.not_nil!.should_not contain("code=")
      end
    end

    it "does not take the decision from a GET" do
      AuthorizationSecuritySpec.with_hook do
        page = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params, user: "john")
        probe = AuthorizationSecuritySpec.authorize("consent_token=#{page.consent_token}&decision=approve", user: "john")
        probe.location.should be_nil
      end
    end

    it "keeps the parameters signed: a POST cannot change scope or redirect_uri" do
      AuthorizationSecuritySpec.with_hook do
        page = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params, user: "john")
        probe = AuthorizationSecuritySpec.decide({"consent_token" => page.consent_token, "decision" => "approve",
                                                  "redirect_uri" => "https://evil.example/", "scope" => "admin"}, user: "john")
        probe.location.not_nil!.should start_with(AuthorizationSecuritySpec::CALLBACK)
      end
    end
  end

  describe "scope and redirect_uri" do
    it "rejects a scope the client may not request (code flow) without asking for consent" do
      AuthorizationSecuritySpec.with_hook do
        probe = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params(scope: "read superuser"), user: "john")
        probe.status.should eq 302
        probe.location.not_nil!.should contain("error=invalid_scope")
        probe.location.not_nil!.should_not contain("code=")
      end
    end

    it "rejects a scope the client may not request (implicit flow) and mints no token" do
      AuthorizationSecuritySpec.with_hook do
        probe = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params(response_type: "token", scope: "superuser"), user: "john")
        probe.location.to_s.should contain("error=invalid_scope")
        probe.location.to_s.should_not contain("access_token")
      end
    end

    it "does not mint an implicit token without a signed-in user" do
      AuthorizationSecuritySpec.with_hook do
        probe = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params(response_type: "token") + "&consent=approved")
        probe.status.should eq 401
        probe.location.should be_nil
      end
    end

    it "mints an implicit token only after a signed consent, for an allowed scope" do
      AuthorizationSecuritySpec.with_hook do
        page = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params(response_type: "token"), user: "john")
        page.status.should eq 200
        probe = AuthorizationSecuritySpec.decide({"consent_token" => page.consent_token, "decision" => "approve"}, user: "john")
        probe.status.should eq 302
        probe.location.not_nil!.should contain("#access_token=")
      end
    end

    it "never redirects or renders for an unregistered redirect_uri" do
      AuthorizationSecuritySpec.with_hook do
        ["https://evil.example/cb", AuthorizationSecuritySpec::XSS, "#{AuthorizationSecuritySpec::CALLBACK}/../x"].each do |uri|
          probe = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params(redirect_uri: uri), user: "john")
          probe.status.should eq 400
          probe.location.should be_nil
          probe.body.should_not contain("<script>")
          probe.body.should_not contain("evil.example")
        end
      end
    end

    it "does not reflect an unknown client_id" do
      AuthorizationSecuritySpec.with_hook do
        probe = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params(client_id: AuthorizationSecuritySpec::XSS), user: "john")
        probe.location.should be_nil
        probe.body.should_not contain("<script>")
      end
    end
  end

  describe "HTML escaping and headers" do
    it "escapes every value on the consent page and sets the hardening headers" do
      Authly.clients << Authly::Client.new("Evil", "s", AuthorizationSecuritySpec::CALLBACK, %(c"><i>1), %(read<b>x&y), "authorization_code")
      AuthorizationSecuritySpec.with_hook do
        page = AuthorizationSecuritySpec.authorize(
          AuthorizationSecuritySpec.params(client_id: %(c"><i>1), scope: %(read<b>x&y), state: AuthorizationSecuritySpec::XSS), user: "john")
        page.status.should eq 200
        body = page.body
        body.should_not contain("<i>")
        body.should_not contain("<b>")
        body.should_not contain("<script>")
        body.should contain("&lt;b&gt;x&amp;y")
        page.header("Content-Security-Policy").to_s.should contain("default-src 'none'")
        page.header("Content-Security-Policy").to_s.should contain("frame-ancestors 'none'")
        page.header("X-Frame-Options").should eq "DENY"
        page.header("X-Content-Type-Options").should eq "nosniff"
        page.header("Cache-Control").should eq "no-store"
        page.header("Referrer-Policy").should eq "no-referrer"
      end
    end
  end

  describe "routing" do
    it "routes GET and POST of /oauth/authorize through Authly::Handler" do
      AuthorizationSecuritySpec.with_hook do
        page = AuthorizationSecuritySpec::Probe.new("GET", "/oauth/authorize?#{AuthorizationSecuritySpec.params}", "john")
        Authly::Handler.new.call(page.context)
        page.status.should eq 200

        post = AuthorizationSecuritySpec::Probe.new("POST", "/oauth/authorize", "john", {"consent_token" => page.consent_token, "decision" => "approve"})
        Authly::Handler.new.call(post.context)
        post.status.should eq 302
      end
    end
  end

  describe "pushed authorization requests" do
    it "uses the pushed parameters only: query scope, redirect_uri, user_id and consent are ignored" do
      AuthorizationSecuritySpec.with_hook do
        pushed = {"client_id" => "1", "response_type" => "code", "redirect_uri" => AuthorizationSecuritySpec::CALLBACK,
                  "scope" => "read", "state" => "par-state"}
        request_uri = "urn:ietf:params:oauth:request_uri:#{Random::Secure.hex(8)}"
        Authly.config.par_store.store(request_uri, pushed, "1", 90.seconds)
        query = "client_id=1&request_uri=#{URI.encode_www_form(request_uri)}&scope=superuser&redirect_uri=https://evil.example/&user_id=admin&consent=approved"
        page = AuthorizationSecuritySpec.authorize(query, user: "john")
        page.status.should eq 200
        page.location.should be_nil
        probe = AuthorizationSecuritySpec.decide({"consent_token" => page.consent_token, "decision" => "approve"}, user: "john")
        probe.location.not_nil!.should start_with(AuthorizationSecuritySpec::CALLBACK)
        AuthorizationSecuritySpec.code_subject(probe.location.not_nil!).should eq "john"
      end
    end

    it "does not store user_id or consent pushed by a client" do
      body = "response_type=code&client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback&user_id=admin&consent=approved"
      request = HTTP::Request.new("POST", "/oauth/par", HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"}, body)
      io = IO::Memory.new
      context = HTTP::Server::Context.new(request, HTTP::Server::Response.new(io))
      Authly::PARHandler.handle(context)
      context.response.close
      io.rewind
      request_uri = JSON.parse(io.gets_to_end.partition("\r\n\r\n")[2])["request_uri"].as_s
      stored = Authly.config.par_store.fetch(request_uri).not_nil!
      stored.params.has_key?("user_id").should be_false
      stored.params.has_key?("consent").should be_false
    end
  end
end

describe Authly::FormToken do
  it "round-trips claims and binds the purpose" do
    token = Authly::FormToken.issue("consent", {"subject" => "john"}, 5.minutes)
    Authly::FormToken.verify("consent", token).not_nil!["subject"].should eq "john"
    Authly::FormToken.verify("device", token).should be_nil
  end

  it "rejects expired, tampered and malformed tokens" do
    Authly::FormToken.verify("consent", Authly::FormToken.issue("consent", {"a" => "b"}, -1.second)).should be_nil
    token = Authly::FormToken.issue("consent", {"subject" => "john"}, 5.minutes)
    payload, _, mac = token.partition('.')
    Authly::FormToken.verify("consent", "#{Base64.urlsafe_encode(%({"subject":"admin"}))}.#{mac}").should be_nil
    Authly::FormToken.verify("consent", "nodot").should be_nil
    Authly::FormToken.verify("consent", "").should be_nil
  end
end

describe "Device verification security" do
  before_each { Authly.config.device_code_store = Authly::InMemoryDeviceCodeStore.new }

  it "fails closed without a hook" do
    AuthorizationSecuritySpec.without_hook do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      probe = AuthorizationSecuritySpec.device_post({"user_code" => data.user_code, "user_id" => "admin", "action" => "approve"})
      probe.status.should eq 500
      Authly.config.device_code_store.fetch(data.device_code).not_nil!.verified?.should be_false
      AuthorizationSecuritySpec.device_get("/device?user_code=#{URI.encode_www_form(AuthorizationSecuritySpec::XSS)}").body.should_not contain("<script>")
    end
  end

  it "does not approve a code from a form user_id, or without a signed-in user, or without the token" do
    AuthorizationSecuritySpec.with_hook do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      form = {"user_code" => data.user_code, "user_id" => "admin", "action" => "approve"}
      AuthorizationSecuritySpec.device_post(form).status.should eq 401
      AuthorizationSecuritySpec.device_post(form, user: "john").status.should eq 400
      AuthorizationSecuritySpec.device_post(form.merge({"csrf_token" => "bogus"}), user: "john").status.should eq 400
      Authly.config.device_code_store.fetch(data.device_code).not_nil!.verified?.should be_false
    end
  end

  it "approves with the authenticated subject and a valid token, once" do
    AuthorizationSecuritySpec.with_hook do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      page = AuthorizationSecuritySpec.device_get("/device?user_code=#{data.user_code}", user: "john")
      page.status.should eq 200
      form = {"user_code" => data.user_code, "user_id" => "admin", "action" => "approve", "csrf_token" => page.csrf_token}
      AuthorizationSecuritySpec.device_post(form, user: "alice").status.should eq 403
      AuthorizationSecuritySpec.device_post(form, user: "john").status.should eq 200
      stored = Authly.config.device_code_store.fetch(data.device_code).not_nil!
      stored.verified?.should be_true
      stored.user_id.should eq "john"
      AuthorizationSecuritySpec.device_post(form, user: "john").status.should eq 400
    end
  end

  it "escapes user_code and sets the hardening headers" do
    AuthorizationSecuritySpec.with_hook do
      page = AuthorizationSecuritySpec.device_get("/device?user_code=#{URI.encode_www_form(AuthorizationSecuritySpec::XSS)}", user: "john")
      page.body.should_not contain("<script>")
      page.body.should contain("&lt;script&gt;")
      page.header("Content-Security-Policy").to_s.should contain("default-src 'none'")
      page.header("X-Frame-Options").should eq "DENY"
      page.header("Cache-Control").should eq "no-store"
    end
  end

  it "escapes error messages" do
    AuthorizationSecuritySpec.with_hook do
      page = AuthorizationSecuritySpec.device_get("/device", user: "john")
      probe = AuthorizationSecuritySpec.device_post({"user_code" => AuthorizationSecuritySpec::XSS, "action" => "approve", "csrf_token" => page.csrf_token}, user: "john")
      probe.body.should_not contain("<script>")
    end
  end

  it "generates user codes with a secure RNG alphabet and shape" do
    Authly::DeviceCode.generate_user_code.should match(/\A[A-Z2-9]{4}-[A-Z2-9]{4}\z/)
  end
end

describe "Authorization endpoint review follow-ups" do
  it "keeps a pushed request_uri for the signed-in user: an anonymous visit does not consume it" do
    AuthorizationSecuritySpec.with_hook do
      Authly.config.login_url = ->(_ctx : HTTP::Server::Context) { "/login" }
      pushed = {"client_id" => "1", "response_type" => "code", "redirect_uri" => AuthorizationSecuritySpec::CALLBACK, "scope" => "read"}
      request_uri = "urn:ietf:params:oauth:request_uri:#{Random::Secure.hex(8)}"
      Authly.config.par_store.store(request_uri, pushed, "1", 90.seconds)
      query = "client_id=1&request_uri=#{URI.encode_www_form(request_uri)}"

      AuthorizationSecuritySpec.authorize(query).location.should eq "/login"
      AuthorizationSecuritySpec.authorize(query, user: "john").status.should eq 200
    end
  end

  it "answers 400 for an unknown client, an unregistered redirect_uri and a grant the client lacks" do
    AuthorizationSecuritySpec.with_hook do
      AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params(client_id: "nobody"), user: "john").status.should eq 400
      AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params(redirect_uri: "https://evil.example/"), user: "john").status.should eq 400
      Authly.clients << Authly::Client.new("CodeOnly", "s", AuthorizationSecuritySpec::CALLBACK, "code-only", "read", "authorization_code")
      probe = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params(client_id: "code-only", response_type: "token"), user: "john")
      probe.status.should eq 400
      probe.location.should be_nil
    end
  end

  it "trims the subject the hook returns" do
    AuthorizationSecuritySpec.with_hook do
      page = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params, user: "  john ")
      probe = AuthorizationSecuritySpec.decide({"consent_token" => page.consent_token, "decision" => "approve"}, user: "john")
      probe.status.should eq 302
    end
  end

  it "rejects a blank scope" do
    AuthorizationSecuritySpec.with_hook do
      probe = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params(scope: " "), user: "john")
      probe.location.to_s.should contain("error=invalid_scope")
    end
  end

  it "ignores empty scope tokens from doubled spaces but never accepts an empty scope" do
    Authly.clients.allowed_scopes?("1", "read  write").should be_true
    Authly.clients.allowed_scopes?("1", "").should be_false
    Authly.clients.allowed_scopes?("1", "  ").should be_false
  end

  it "submits the consent form to the path it was served from" do
    AuthorizationSecuritySpec.with_hook do
      probe = AuthorizationSecuritySpec::Probe.new("GET", "/auth/oauth/authorize?#{AuthorizationSecuritySpec.params}", "john")
      Authly::AuthorizationHandler.handle(probe.context)
      probe.body.should contain(%(action="/auth/oauth/authorize"))
    end
  end

  it "serves the form_post.jwt page without an inline handler, under a CSP, not framable or cacheable" do
    previous = Authly.config.jarm_signing_alg
    Authly.config.jarm_signing_alg = JWT::Algorithm::HS256
    AuthorizationSecuritySpec.with_hook do
      page = AuthorizationSecuritySpec.authorize(AuthorizationSecuritySpec.params(response_mode: "form_post.jwt"), user: "john")
      probe = AuthorizationSecuritySpec.decide({"consent_token" => page.consent_token, "decision" => "approve"}, user: "john")
      probe.status.should eq 200
      probe.body.should_not contain("onload")
      probe.header("Content-Security-Policy").to_s.should contain("script-src 'sha256-")
      probe.header("X-Frame-Options").should eq "DENY"
      probe.header("Cache-Control").should eq "no-store"
    end
  ensure
    Authly.config.jarm_signing_alg = previous.not_nil!
  end

  it "shows the client and scope on the device confirmation step, escaped" do
    Authly.config.device_code_store = Authly::InMemoryDeviceCodeStore.new
    AuthorizationSecuritySpec.with_hook do
      data = Authly::DeviceCode.create_device_authorization(%(c"><i>1), %(read<b>x))
      page = AuthorizationSecuritySpec.device_get("/device?user_code=#{data.user_code}", user: "john")
      page.body.should contain("c&quot;&gt;&lt;i&gt;1")
      page.body.should contain("read&lt;b&gt;x")
      page.body.should_not contain("<i>")
      page.body.should_not contain("<b>")
    end
  end

  it "submits the device form to the path it was served from" do
    AuthorizationSecuritySpec.with_hook do
      page = AuthorizationSecuritySpec.device_get("/auth/device", user: "john")
      page.body.should contain(%(action="/auth/device"))
    end
  end
end

describe Authly::InMemoryStateStore do
  it "consume answers true once, false for a replay, an unknown or an expired state" do
    store = Authly::InMemoryStateStore.new
    store.store("a")
    store.consume("a").should be_true
    store.consume("a").should be_false
    store.consume("unknown").should be_false
    store.store("b", -1.second)
    store.consume("b").should be_false
  end

  it "drops expired states as new ones are stored" do
    store = Authly::InMemoryStateStore.new
    300.times { |i| store.store("old-#{i}", -1.second) }
    store.size.should be < 100
  end
end
