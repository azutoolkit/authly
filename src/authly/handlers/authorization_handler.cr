require "html"
require "http/server/handler"
require "uri"

module Authly
  # The parameters of one authorization request, as the client sent them (directly or pushed).
  record AuthorizationRequest,
    client_id : String,
    redirect_uri : String,
    response_type : String,
    response_mode : String,
    scope : String,
    code_challenge : String,
    challenge_method : String,
    state : String do
    def self.from_params(params : Hash(String, String)) : self
      new(
        params.fetch("client_id", ""), params.fetch("redirect_uri", ""), params.fetch("response_type", ""),
        params.fetch("response_mode", ""), params.fetch("scope", ""), params.fetch("code_challenge", ""),
        params.fetch("code_challenge_method", ""), params.fetch("state", ""))
    end

    def to_claims : Hash(String, String)
      {
        "client_id" => client_id, "redirect_uri" => redirect_uri, "response_type" => response_type,
        "response_mode" => response_mode, "scope" => scope, "code_challenge" => code_challenge,
        "code_challenge_method" => challenge_method, "state" => state,
      }
    end

    def implicit? : Bool
      response_type == "token"
    end
  end

  # The authorization endpoint.
  #
  # GET shows the consent page to the signed-in resource owner; POST carries the owner's decision.
  # The owner is whoever `Authly.config.authenticate_user` says is signed in: no request parameter
  # ever names the subject or grants consent. The consent form carries a signed token that binds the
  # request parameters to that subject (see `FormToken`), which is also the anti-CSRF token.
  class AuthorizationHandler
    CONSENT = "consent"

    def self.handle(context)
      authenticator = Authly.config.authenticate_user
      return not_configured(context) unless authenticator

      case context.request.method
      when "GET"  then show_consent(context, authenticator)
      when "POST" then decide(context, authenticator)
      else
        ResponseHelper.write(context, 405, "text/plain", "Method not allowed")
      end
    rescue e : Error
      ResponseHelper.write(context, e.code, "text/plain", e.message)
    end

    private def self.not_configured(context)
      Log.error { "Authly.config.authenticate_user is not set: the authorization endpoint refuses every request" }
      ResponseHelper.write(context, 500, "text/plain",
        "The authorization endpoint is not configured: set Authly.config.authenticate_user")
    end

    private def self.show_consent(context, authenticator)
      return par_required(context) if par_required?(context)

      # Sign in first: loading a pushed request consumes its request_uri, which must survive the login detour
      subject = signed_in_subject(context, authenticator)
      return unless subject

      request = load_request(context)
      validate!(request)
      return redirect_error(context, request, "invalid_scope") unless scope_allowed?(request)

      nonce = Random::Secure.hex(16)
      Authly.config.state_store.store(nonce, Authly.config.consent_ttl)
      claims = request.to_claims.merge({"subject" => subject, "nonce" => nonce})
      token = FormToken.issue(CONSENT, claims, Authly.config.consent_ttl)
      ResponseHelper.write_page(context, 200, consent_page(context, request, subject, token))
    end

    private def self.decide(context, authenticator)
      subject = signed_in_subject(context, authenticator)
      return unless subject

      claims = FormToken.verify(CONSENT, context.request.form_params.fetch("consent_token", ""))
      return invalid_consent(context, 400) unless claims
      return invalid_consent(context, 403) unless claims["subject"]? == subject
      return invalid_consent(context, 400) unless consume_nonce(claims["nonce"]?)

      request = AuthorizationRequest.from_params(claims)
      validate!(request)
      return redirect_error(context, request, "invalid_scope") unless scope_allowed?(request)

      case context.request.form_params.fetch("decision", "")
      when "approve" then issue(context, request, subject)
      when "deny"    then redirect_error(context, request, "access_denied")
      else                ResponseHelper.write(context, 400, "text/plain", "Invalid decision")
      end
    end

    private def self.consume_nonce(nonce : String?) : Bool
      return false unless nonce
      Authly.config.state_store.consume(nonce)
    end

    private def self.invalid_consent(context, status : Int32)
      ResponseHelper.write(context, status, "text/plain", "Invalid or expired consent token")
    end

    # The signed-in owner, or nil after answering with the login redirect / 401.
    private def self.signed_in_subject(context, authenticator) : String?
      subject = authenticator.call(context).try(&.strip).presence
      return subject if subject

      if login_url = Authly.config.login_url
        ResponseHelper.redirect(context, login_url.call(context))
      else
        ResponseHelper.write(context, 401, "application/json", {
          error:             "login_required",
          error_description: "The resource owner must sign in",
        }.to_json)
      end
      nil
    end

    private def self.par_required?(context) : Bool
      Authly.config.require_par? && !context.request.query_params.has_key?("request_uri")
    end

    private def self.par_required(context)
      ResponseHelper.write(context, 400, "application/json", {
        error:             "invalid_request",
        error_description: "Pushed Authorization Request is required",
      }.to_json)
    end

    # The request parameters: query for a plain request, only what was pushed for a PAR request_uri.
    private def self.load_request(context) : AuthorizationRequest
      query_params = context.request.query_params

      if request_uri = query_params["request_uri"]?
        return AuthorizationRequest.from_params(load_par_params(request_uri, query_params))
      end

      AuthorizationRequest.from_params(query_params.to_h)
    end

    # Everything the redirect depends on is checked against the client's registration before anything
    # is rendered or redirected: a request that fails here is never answered with a redirect.
    private def self.validate!(request : AuthorizationRequest) : Nil
      raise Error.invalid_redirect_uri if request.redirect_uri.empty?
      raise Error.invalid_redirect_uri unless Authly.clients.valid_redirect?(request.client_id, request.redirect_uri)
      raise Error.invalid_response_type unless ["code", "token"].includes?(request.response_type)
      raise Error(400).new(:unauthorized_client) unless Authly.clients.allowed_grant_type?(request.client_id, grant_type(request))

      validate_pkce!(request.client_id, request.code_challenge, request.challenge_method)
    end

    private def self.grant_type(request : AuthorizationRequest) : String
      request.implicit? ? "implicit" : "authorization_code"
    end

    private def self.scope_allowed?(request : AuthorizationRequest) : Bool
      !request.scope.blank? && Authly.clients.allowed_scopes?(request.client_id, request.scope)
    end

    # `validate!` already matched the client, redirect_uri, grant type and scope, so the implicit token
    # is built here, for the authenticated subject, instead of through `Authly.code` (which gives an
    # implicit token a random subject).
    private def self.issue(context, request : AuthorizationRequest, subject : String)
      use_jarm = should_use_jarm?(request.client_id, request.response_mode)

      if request.implicit?
        token = AccessToken.new(request.client_id, request.scope, subject: subject)
        respond_with_token(context, request, token, use_jarm)
      else
        code = Authly.code(request.response_type, request.client_id, request.redirect_uri, request.scope,
          request.code_challenge, request.challenge_method, subject)
        respond_with_code(context, request, code.to_s, use_jarm)
      end
    end

    private def self.respond_with_code(context, request : AuthorizationRequest, code : String, use_jarm : Bool)
      if use_jarm
        handle_jarm_response(context, request.client_id, request.redirect_uri, request.response_mode, code, request.state)
      else
        redirect_to(context, request.redirect_uri, {"code" => code, "state" => request.state}, fragment: false)
      end
    end

    private def self.respond_with_token(context, request : AuthorizationRequest, token : AccessToken, use_jarm : Bool)
      if use_jarm
        handle_jarm_response(context, request.client_id, request.redirect_uri, request.response_mode, nil, request.state,
          token.access_token, "Bearer", token.expires_in, request.scope, token.id_token)
      else
        redirect_to(context, request.redirect_uri, {
          "access_token" => token.access_token, "token_type" => "Bearer", "expires_in" => token.expires_in.to_s,
          "scope" => request.scope, "state" => request.state,
        }, fragment: true)
      end
    end

    # An error answer for a request whose redirect_uri was already matched against the registration.
    private def self.redirect_error(context, request : AuthorizationRequest, error : String)
      redirect_to(context, request.redirect_uri, {"error" => error, "state" => request.state}, fragment: request.implicit?)
    end

    private def self.redirect_to(context, redirect_uri : String, params : Hash(String, String), fragment : Bool)
      location = URI.parse(redirect_uri)
      encoded = URI::Params.build do |form|
        params.each { |key, value| form.add(key, value) unless value.empty? }
      end

      if fragment
        location.fragment = encoded
      else
        location.query = [location.query.presence, encoded].compact.join("&")
      end
      ResponseHelper.redirect(context, location.to_s)
    end

    private def self.consent_page(context, request : AuthorizationRequest, subject : String, token : String) : String
      <<-HTML
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="utf-8">
            <title>Authorization Request</title>
          </head>
          <body>
            <h1>Authorization Request</h1>
            <p>Signed in as: #{HTML.escape(subject)}</p>
            <p>Client ID: #{HTML.escape(request.client_id)}</p>
            <p>Requested Scopes: #{HTML.escape(request.scope)}</p>
            <form action="#{HTML.escape(context.request.path)}" method="post">
              <input type="hidden" name="consent_token" value="#{HTML.escape(token)}">
              <button type="submit" name="decision" value="approve">Approve</button>
              <button type="submit" name="decision" value="deny">Deny</button>
            </form>
          </body>
        </html>
        HTML
    end

    private def self.validate_pkce!(client_id, code_challenge, challenge_method)
      # Skip validation if PKCE is not enforced
      return unless Authly.config.enforce_pkce?

      # Determine if client is public (typically indicated by empty or missing secret for public clients)
      # For now, we enforce PKCE for all clients when enforce_pkce is true
      if code_challenge.empty?
        raise Error(400).new(:invalid_request)
      end

      if challenge_method.empty?
        raise Error(400).new(:invalid_request)
      end

      # Enforce S256 method if configured
      if Authly.config.enforce_pkce_s256? && challenge_method != "S256"
        raise Error(400).new(:invalid_request)
      end

      # Validate challenge method is supported
      unless ["plain", "S256"].includes?(challenge_method)
        raise Error(400).new(:invalid_request)
      end
    end

    # The parameters pushed by the client. Nothing in the query string can add to or override them.
    private def self.load_par_params(request_uri : String, query_params : HTTP::Params) : Hash(String, String)
      par_data = Authly.config.par_store.fetch(request_uri)
      raise Error.invalid_request_uri unless par_data

      query_client_id = query_params["client_id"]?
      raise Error.invalid_request_uri if query_client_id && query_client_id != par_data.client_id

      # The request_uri is single-use
      Authly.config.par_store.consume(request_uri)

      par_data.params.dup.tap { |params| params["client_id"] = par_data.client_id }
    end

    # Determine if JARM should be used for this authorization response
    private def self.should_use_jarm?(client_id : String, response_mode : String) : Bool
      # Check if response_mode explicitly requests JARM
      return true if ["query.jwt", "fragment.jwt", "form_post.jwt", "jwt"].includes?(response_mode)

      # Check if client requires JARM
      return true if Authly.clients.jarm_required?(client_id)

      # Check if global default JARM response mode is set
      return true if Authly.config.default_jarm_response_mode

      false
    end

    # Handle JARM response (JWT-secured authorization response)
    private def self.handle_jarm_response(
      context,
      client_id : String,
      redirect_uri : String,
      response_mode : String,
      code : String? = nil,
      state : String? = nil,
      access_token : String? = nil,
      token_type : String? = nil,
      expires_in : Int64? = nil,
      scope : String? = nil,
      id_token : String? = nil,
    )
      # Determine response mode (use client/global default if not specified)
      mode = response_mode
      if mode.empty?
        mode = Authly.config.default_jarm_response_mode || "query.jwt"
      end

      # Get signing key and algorithm
      signing_key = Authly.config.jarm_signing_key || Authly.config.secret_key
      signing_alg_name = Authly.clients.jarm_signing_algorithm(client_id)
      signing_alg = parse_jwt_algorithm(signing_alg_name) || Authly.config.jarm_signing_alg

      # Get optional encryption settings
      encryption_key = Authly.clients.client_public_key(client_id) || Authly.config.jarm_encryption_key
      encryption_alg = Authly.clients.jarm_encryption_algorithm(client_id) || Authly.config.jarm_encryption_alg
      encryption_enc = Authly.clients.jarm_encryption_encoding(client_id) || Authly.config.jarm_encryption_enc

      # Build JARM JWT
      jarm_builder = JarmBuilder.new(
        issuer: Authly.config.issuer,
        audience: client_id,
        lifetime: Authly.config.jarm_lifetime,
        signing_key: signing_key,
        signing_algorithm: signing_alg,
        encryption_key: encryption_key,
        encryption_algorithm: encryption_alg,
        encryption_encoding: encryption_enc
      )

      jwt_response = jarm_builder.build_authorization_response(
        code: code,
        state: state,
        access_token: access_token,
        token_type: token_type,
        expires_in: expires_in,
        scope: scope,
        id_token: id_token
      )

      # Return response based on mode
      case mode
      when "query.jwt"
        # JWT in query parameter
        redirect_location = URI.parse(redirect_uri)
        redirect_location.query = "response=#{URI.encode_www_form(jwt_response)}"
        ResponseHelper.redirect(context, redirect_location.to_s)
      when "fragment.jwt"
        # JWT in fragment
        redirect_location = URI.parse(redirect_uri)
        redirect_location.fragment = "response=#{jwt_response}"
        ResponseHelper.redirect(context, redirect_location.to_s)
      when "form_post.jwt"
        # Auto-submit HTML form with JWT
        html = JarmBuilder.build_form_post_html(redirect_uri, jwt_response)
        ResponseHelper.write_page(context, 200, html, script_src: JarmBuilder::FORM_POST_SCRIPT)
      when "jwt"
        # Direct JWT response (for JAR flows)
        ResponseHelper.write(context, 200, "application/jwt", jwt_response)
      else
        raise Error.invalid_request
      end
    end

    # Parse JWT algorithm name to JWT::Algorithm
    private def self.parse_jwt_algorithm(alg_name : String?) : JWT::Algorithm?
      return unless alg_name

      case alg_name
      when "HS256" then JWT::Algorithm::HS256
      when "HS384" then JWT::Algorithm::HS384
      when "HS512" then JWT::Algorithm::HS512
      when "RS256" then JWT::Algorithm::RS256
      when "RS384" then JWT::Algorithm::RS384
      when "RS512" then JWT::Algorithm::RS512
      when "ES256" then JWT::Algorithm::ES256
      when "ES384" then JWT::Algorithm::ES384
      when "ES512" then JWT::Algorithm::ES512
      end
    end
  end
end
