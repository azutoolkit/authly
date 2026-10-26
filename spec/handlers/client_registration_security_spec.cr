require "../spec_helper"

module RegistrationSpec
  TOKEN = "initial-access-token"

  class Probe
    getter context : HTTP::Server::Context

    def initialize(body : String, headers : HTTP::Headers)
      @io = IO::Memory.new
      @context = HTTP::Server::Context.new(HTTP::Request.new("POST", "/oauth/register", headers, body), HTTP::Server::Response.new(@io))
    end

    def status : Int32
      @context.response.status_code
    end

    def header(name : String) : String?
      @context.response.headers[name]?
    end

    def text : String
      @context.response.close
      @io.rewind
      @io.gets_to_end.partition("\r\n\r\n")[2]
    end

    def json : JSON::Any
      JSON.parse(text)
    end
  end

  def self.configured(token : String? = TOKEN, &)
    config = Authly.config
    saved = {config.allow_dynamic_registration?, config.registration_access_token, config.authenticate_registration,
             config.client_store, config.attempt_limiter, config.attempt_source}
    config.allow_dynamic_registration = true
    config.registration_access_token = token
    config.authenticate_registration = nil
    config.client_store = Authly::InMemoryClientStore.new
    config.attempt_limiter = Authly::InMemoryAttemptLimiter.new
    config.registration_rate_limit = 1000
    begin
      yield
    ensure
      restore(saved)
    end
  end

  def self.restore(saved)
    config = Authly.config
    config.allow_dynamic_registration, config.registration_access_token, config.authenticate_registration, config.client_store, config.attempt_limiter, config.attempt_source = saved
    config.registration_grant_types = ["authorization_code", "refresh_token"]
    config.registration_response_types = ["code"]
    config.registration_scopes = [] of String
    config.registration_rate_limit = 10
  end

  # Counts what reaches the store
  class CountingStore
    include Authly::ClientStore
    getter stored = 0

    def store(client : Authly::DynamicClient) : Bool
      @stored += 1
      true
    end

    def fetch(client_id : String) : Authly::DynamicClient?
      nil
    end

    def delete(client_id : String) : Bool
      false
    end

    def update(client : Authly::DynamicClient) : Bool
      false
    end
  end

  def self.register(metadata, token : String? = TOKEN, headers : HTTP::Headers = HTTP::Headers.new) : Probe
    headers["Authorization"] = "Bearer #{token}" if token
    probe = Probe.new(metadata.is_a?(String) ? metadata : metadata.to_json, headers)
    Authly::ClientRegistrationHandler.handle(probe.context)
    probe
  end

  def self.callback(uris : Array(String)) : Hash(String, JSON::Any)
    {"redirect_uris" => JSON::Any.new(uris.map { |uri| JSON::Any.new(uri) })}
  end

  def self.stored?(client_id : String) : Bool
    !Authly.config.client_store.fetch(client_id).nil?
  end
end

describe "Dynamic client registration security" do
  describe "who may register" do
    it "refuses everyone while neither an initial access token nor a hook is configured" do
      RegistrationSpec.configured(token: nil) do
        probe = RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]}, token: nil)
        probe.status.should eq 500
        probe.text.should contain("registration_access_token")
      end
    end

    it "refuses an anonymous request" do
      RegistrationSpec.configured do
        probe = RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]}, token: nil)
        probe.status.should eq 401
        probe.header("WWW-Authenticate").should eq "Bearer"
        probe.text.should_not contain("client_secret")
      end
    end

    it "refuses a wrong or truncated initial access token" do
      RegistrationSpec.configured do
        [RegistrationSpec::TOKEN + "x", RegistrationSpec::TOKEN[0, 5], "", "Bearer"].each do |token|
          RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]}, token: token).status.should eq 401
        end
      end
    end

    it "refuses a token sent in a different scheme" do
      RegistrationSpec.configured do
        headers = HTTP::Headers{"Authorization" => "Basic #{RegistrationSpec::TOKEN}"}
        probe = RegistrationSpec::Probe.new({redirect_uris: ["https://example.com/cb"]}.to_json, headers)
        Authly::ClientRegistrationHandler.handle(probe.context)
        probe.status.should eq 401
      end
    end

    it "registers with the initial access token" do
      RegistrationSpec.configured do
        probe = RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]})
        probe.status.should eq 201
        RegistrationSpec.stored?(probe.json["client_id"].as_s).should be_true
      end
    end

    it "asks the authentication hook, which can refuse and can accept" do
      RegistrationSpec.configured(token: nil) do
        Authly.config.authenticate_registration = ->(_context : HTTP::Server::Context) { false }
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]}, token: nil).status.should eq 401

        Authly.config.authenticate_registration = ->(context : HTTP::Server::Context) { context.request.headers["X-Admin"]? == "yes" }
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]}, token: nil).status.should eq 401
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]}, token: nil, headers: HTTP::Headers{"X-Admin" => "yes"}).status.should eq 201
      end
    end

    it "stores nothing for a refused request" do
      RegistrationSpec.configured do
        store = RegistrationSpec::CountingStore.new
        Authly.config.client_store = store
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]}, token: nil)
        RegistrationSpec.register({redirect_uris: ["javascript://x/%0aalert(1)"]})
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"], grant_types: ["password"]})
        store.stored.should eq 0
      end
    end
  end

  describe "what may be registered" do
    it "refuses password, implicit and client_credentials by default" do
      RegistrationSpec.configured do
        ["password", "implicit", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"].each do |grant|
          probe = RegistrationSpec.register({redirect_uris: ["https://example.com/cb"], grant_types: ["authorization_code", grant]})
          probe.status.should eq 400
          probe.json["error"].should eq "invalid_client_metadata"
        end
      end
    end

    it "accepts the allow-list and lets the host widen it" do
      RegistrationSpec.configured do
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"], grant_types: ["authorization_code", "refresh_token"]}).status.should eq 201
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"], grant_types: ["client_credentials"]}).status.should eq 400
        Authly.config.registration_grant_types << "client_credentials"
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"], grant_types: ["client_credentials"]}).status.should eq 201
      end
    end

    it "refuses response types outside the allow-list" do
      RegistrationSpec.configured do
        ["token", "id_token", "code token"].each do |type|
          RegistrationSpec.register({redirect_uris: ["https://example.com/cb"], response_types: [type]}).status.should eq 400
        end
      end
    end

    it "refuses any scope until the host lists some, then only those" do
      RegistrationSpec.configured do
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"], scope: "read"}).status.should eq 400
        Authly.config.registration_scopes = ["read", "profile"]
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"], scope: "read profile"}).status.should eq 201
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"], scope: "read admin"}).status.should eq 400
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]}).status.should eq 201
      end
    end
  end

  describe "redirect URIs" do
    it "refuses schemes that run code or read files" do
      RegistrationSpec.configured do
        ["javascript://x/%0aalert(1)", "javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "vbscript://x/y", "ftp://example.com/cb"].each do |uri|
          RegistrationSpec.register(RegistrationSpec.callback([uri])).status.should eq 400
        end
      end
    end

    it "accepts https, loopback http and reverse-domain private schemes only" do
      RegistrationSpec.configured do
        ["https://example.com/cb", "https://example.com:8443/a/b?x=1", "http://localhost:8080/cb", "http://127.0.0.1:9/cb",
         "http://[::1]:3000/cb", "com.example.app:/oauth2redirect"].each do |uri|
          RegistrationSpec.register(RegistrationSpec.callback([uri])).status.should eq 201
        end
        ["http://example.com/cb", "http://localhost.evil.com/cb", "app:/cb", "myscheme://cb", "/cb", "example.com/cb", "https:///cb"].each do |uri|
          RegistrationSpec.register(RegistrationSpec.callback([uri])).status.should eq 400
        end
      end
    end

    it "refuses fragments, wildcards, user info and control characters" do
      RegistrationSpec.configured do
        ["https://example.com/cb#frag", "https://*.example.com/cb", "https://example.com/*", "https://example.com/cb*",
         "https://user:pw@example.com/cb", "https://user@example.com/cb", "https://example.com/c b", "https://example.com/c\nb", "https://exa mple.com/"].each do |uri|
          RegistrationSpec.register(RegistrationSpec.callback([uri])).status.should eq 400
        end
      end
    end

    it "refuses an empty list, too many entries, an over-long entry and non-strings" do
      RegistrationSpec.configured do
        RegistrationSpec.register({redirect_uris: [] of String}).status.should eq 400
        RegistrationSpec.register(RegistrationSpec.callback(Array.new(11) { |i| "https://example.com/cb#{i}" })).status.should eq 400
        RegistrationSpec.register(RegistrationSpec.callback(["https://example.com/" + "a" * 3000])).status.should eq 400
        probe = RegistrationSpec.register(%({"redirect_uris": [1, {"a": 2}]}))
        probe.status.should eq 400
        probe.text.should_not contain("Cast")
      end
    end

    it "keeps other metadata URIs to https" do
      RegistrationSpec.configured do
        %w[client_uri logo_uri tos_uri policy_uri jwks_uri].each do |field|
          bad = {"redirect_uris" => ["https://example.com/cb"], field => "javascript://x/%0aalert(1)"}
          RegistrationSpec.register(bad).status.should eq 400
          RegistrationSpec.register({"redirect_uris" => ["https://example.com/cb"], field => "http://example.com/x"}).status.should eq 400
          RegistrationSpec.register({"redirect_uris" => ["https://example.com/cb"], field => "https://example.com/x"}).status.should eq 201
        end
      end
    end
  end

  describe "request size and rate" do
    it "refuses a body over the cap without reading it all into a client" do
      RegistrationSpec.configured do
        huge = {redirect_uris: ["https://example.com/cb"], client_name: "x" * (Authly.config.registration_max_body + 1)}
        probe = RegistrationSpec.register(huge)
        probe.status.should eq 413
      end
    end

    it "limits registrations per source" do
      RegistrationSpec.configured do
        Authly.config.registration_rate_limit = 3
        Authly.config.attempt_source = ->(_context : HTTP::Server::Context) { "203.0.113.5".as(String?) }
        statuses = Array.new(5) { RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]}).status }
        statuses.should eq [201, 201, 201, 429, 429]

        Authly.config.attempt_source = ->(_context : HTTP::Server::Context) { "198.51.100.1".as(String?) }
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]}).status.should eq 201
      end
    end

    it "counts requests with a wrong token, so the token cannot be guessed freely" do
      RegistrationSpec.configured do
        Authly.config.registration_rate_limit = 3
        Authly.config.attempt_source = ->(_context : HTTP::Server::Context) { "203.0.113.5".as(String?) }
        3.times { RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]}, token: "guess").status.should eq 401 }
        RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]}).status.should eq 429
      end
    end
  end

  describe "credentials" do
    it "generates a long random secret per client and none for public clients" do
      RegistrationSpec.configured do
        secrets = Array.new(3) { RegistrationSpec.register({redirect_uris: ["https://example.com/cb"]}).json["client_secret"].as_s }
        secrets.uniq.size.should eq 3
        secrets.each(&.should(match(/\A[0-9a-f]{64}\z/)))

        public_client = RegistrationSpec.register({redirect_uris: ["https://example.com/cb"], token_endpoint_auth_method: "none"}).json
        public_client["client_secret"]?.should be_nil
      end
    end
  end
end
