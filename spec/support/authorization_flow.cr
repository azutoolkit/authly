require "http/server"

# Helpers for driving the authorization endpoint and the device page in specs.
module AuthorizationSecuritySpec
  CALLBACK = "https://www.example.com/callback"
  XSS      = %("><script>alert(1)</script>)

  class Probe
    getter context : HTTP::Server::Context

    def initialize(method : String, target : String, user : String? = nil, form : Hash(String, String)? = nil)
      headers = HTTP::Headers.new
      headers["X-Test-User"] = user if user
      body = nil
      if form
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = HTTP::Params.encode(form)
      end
      @io = IO::Memory.new
      @context = HTTP::Server::Context.new(
        HTTP::Request.new(method, target, headers, body),
        HTTP::Server::Response.new(@io))
    end

    def status : Int32
      @context.response.status_code
    end

    def location : String?
      @context.response.headers["Location"]?
    end

    def header(name : String) : String?
      @context.response.headers[name]?
    end

    def body : String
      @context.response.close
      @io.rewind
      text = @io.gets_to_end
      text.partition("\r\n\r\n")[2]
    end

    def consent_token : String
      body.match!(/name="consent_token" value="([^"]+)"/)[1]
    end

    def csrf_token : String
      body.match!(/name="csrf_token" value="([^"]+)"/)[1]
    end
  end

  def self.authorize(query : String, user : String? = nil)
    probe = Probe.new("GET", "/oauth/authorize?#{query}", user)
    Authly::AuthorizationHandler.handle(probe.context)
    probe
  end

  def self.decide(form : Hash(String, String), user : String? = nil)
    probe = Probe.new("POST", "/oauth/authorize", user, form)
    Authly::AuthorizationHandler.handle(probe.context)
    probe
  end

  def self.params(**extra) : String
    base = {"response_type" => "code", "client_id" => "1", "redirect_uri" => CALLBACK, "scope" => "read", "state" => "st-1"}
    extra.each { |key, value| base[key.to_s] = value }
    HTTP::Params.encode(base)
  end

  def self.code_subject(location : String) : String
    code = URI.parse(location).query_params["code"]
    Authly.jwt_decode(code)[0]["user_id"].as_s
  end

  def self.device_post(form : Hash(String, String), user : String? = nil)
    probe = Probe.new("POST", "/device", user, form)
    Authly::DeviceVerificationHandler.handle(probe.context)
    probe
  end

  def self.device_get(target : String, user : String? = nil)
    probe = Probe.new("GET", target, user)
    Authly::DeviceVerificationHandler.handle(probe.context)
    probe
  end

  # A signed-in owner submitting the device form with a fresh token
  def self.device_submit(user_code : String, action : String, user : String = "test_user")
    page = device_get("/device", user)
    device_post({"user_code" => user_code, "action" => action, "csrf_token" => page.csrf_token}, user)
  end

  def self.with_hook(&)
    previous = {Authly.config.authenticate_user, Authly.config.login_url}
    Authly.config.authenticate_user = ->(ctx : HTTP::Server::Context) { ctx.request.headers["X-Test-User"]?.presence }
    Authly.config.login_url = nil
    yield
  ensure
    Authly.config.authenticate_user, Authly.config.login_url = previous.not_nil!
  end

  def self.without_hook(&)
    previous = Authly.config.authenticate_user
    Authly.config.authenticate_user = nil
    yield
  ensure
    Authly.config.authenticate_user = previous
  end

  # The whole consent round trip for `user`: GET the consent page, then POST the approval.
  # Returns the GET answer when it is not a consent page (error, login, scope error).
  def self.approve(query : String, user : String? = "user123")
    page = authorize(query, user)
    return page unless page.status == 200 && page.body.includes?("consent_token")

    decide({"consent_token" => page.consent_token, "decision" => "approve"}, user)
  end
end
