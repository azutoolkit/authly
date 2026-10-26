require "json"
require "crypto/subtle"
require "digest/sha256"

module Authly
  # RFC 7591 registration. It is never anonymous: the caller presents the initial access token
  # (`Authly.config.registration_access_token`, as `Authorization: Bearer`) or satisfies
  # `Authly.config.authenticate_registration`; while neither is configured the endpoint refuses everything.
  # What may be registered is bounded by `RegistrationPolicy`. Only failed authentications are counted per source
  # (`registration_rate_limit` per `registration_rate_window`): they are what guesses the initial access token. A source
  # that used up its failures is refused even with the right token until the window passes, so the limit caps the guesses.
  # Behind a reverse proxy see `Configuration#attempt_source`: the source is only as trustworthy as that hook.
  class ClientRegistrationHandler
    def self.handle(context)
      unless Authly.config.allow_dynamic_registration?
        return error(context, 403, "access_denied", "Dynamic client registration is not enabled")
      end
      return not_configured(context) unless configured?
      return refused(context) unless authorized?(context)
      return too_many_requests(context) if locked_out?(context)

      body = read_body(context)
      return error(context, 413, "invalid_request", "Request body is too large") unless body
      return error(context, 400, "invalid_request", "Request body is required") if body.empty?

      register(context, body)
    end

    private def self.register(context, body : String)
      params = JSON.parse(body).as_h
      unless params["redirect_uris"]?
        return error(context, 400, "invalid_request", "redirect_uris is required")
      end

      client = DynamicClient.from_registration_request(params)
      violation = RegistrationPolicy.new.violation(client)
      return error(context, 400, violation.error, violation.description) if violation
      return error(context, 400, "invalid_client_metadata", "Client metadata validation failed") unless client.valid?
      return error(context, 500, "server_error", "Failed to store client registration") unless Authly.config.client_store.store(client)

      ResponseHelper.write(context, 201, "application/json", client.to_json)
    rescue JSON::ParseException
      error(context, 400, "invalid_request", "Invalid JSON in request body")
    rescue e : Error
      error(context, e.code, e.type.to_s, e.message.to_s)
    rescue Exception
      error(context, 400, "invalid_client_metadata", "Client metadata is malformed")
    end

    private def self.configured? : Bool
      !Authly.config.authenticate_registration.nil? || !Authly.config.registration_access_token.presence.nil?
    end

    private def self.not_configured(context)
      Log.error { "Dynamic registration is on but neither registration_access_token nor authenticate_registration is set: every request is refused" }
      error(context, 500, "server_error",
        "Dynamic registration is not configured: set Authly.config.registration_access_token or authenticate_registration")
    end

    private def self.authorized?(context) : Bool
      hook = Authly.config.authenticate_registration
      return true if hook && hook.call(context)

      expected = Authly.config.registration_access_token.presence
      presented = context.request.headers["Authorization"]?.try(&.match(/\ABearer (.+)\z/i)).try(&.[1])
      !expected.nil? && !presented.nil? && same_secret?(expected, presented)
    end

    # Compared as digests, so neither the value nor its length leaks through timing.
    private def self.same_secret?(expected : String, presented : String) : Bool
      Crypto::Subtle.constant_time_compare(Digest::SHA256.digest(expected), Digest::SHA256.digest(presented))
    end

    # A failed authentication is counted with one atomic `increment`; the answer is 429 once the source is over the
    # limit and 401 until then.
    private def self.refused(context)
      config = Authly.config
      count = config.attempt_limiter.increment(attempt_key(context), config.registration_rate_window)
      count > config.registration_rate_limit ? too_many_requests(context) : unauthorized(context)
    end

    private def self.locked_out?(context) : Bool
      Authly.config.attempt_limiter.exceeded?(attempt_key(context), Authly.config.registration_rate_limit)
    end

    private def self.attempt_key(context) : String
      "register:source:#{Authly.config.attempt_source.call(context) || "unknown"}"
    end

    private def self.too_many_requests(context)
      context.response.headers["Retry-After"] = Authly.config.registration_rate_window.total_seconds.to_i.to_s
      error(context, 429, "access_denied", "Too many registration requests")
    end

    # nil when the body is over `registration_max_body`; never more than one byte past it is read.
    private def self.read_body(context) : String?
      limit = Authly.config.registration_max_body
      buffer = IO::Memory.new
      context.request.body.try { |body| IO.copy(body, buffer, limit + 1) }
      buffer.to_s if buffer.size <= limit
    end

    private def self.unauthorized(context)
      context.response.headers["WWW-Authenticate"] = "Bearer"
      error(context, 401, "invalid_token", "A valid initial access token is required")
    end

    private def self.error(context, status : Int32, error : String, description : String)
      ResponseHelper.write(context, status, "application/json", {error: error, error_description: description}.to_json)
    end
  end
end
