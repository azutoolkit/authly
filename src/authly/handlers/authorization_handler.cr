require "http/server/handler"
require "uri"

module Authly
  class AuthorizationHandler
    def self.handle(context)
      query_params = context.request.query_params

      # Check if request_uri is present (PAR flow)
      request_uri = query_params["request_uri"]?

      # Load parameters from PAR store if request_uri is present
      if request_uri
        params = load_par_params(request_uri, query_params)
      else
        # Check if PAR is required
        if Authly.config.require_par?
          ResponseHelper.write(context, 400, "application/json", {
            error:             "invalid_request",
            error_description: "Pushed Authorization Request is required",
          }.to_json)
          return
        end
        params = query_params
      end

      client_id = params.fetch("client_id", "")
      redirect_uri = params.fetch("redirect_uri", "")
      response_type = params.fetch("response_type", "")
      response_mode = params.fetch("response_mode", "")
      scope = params.fetch("scope", "")
      code_challenge = params.fetch("code_challenge", "")
      challenge_method = params.fetch("code_challenge_method", "")
      user_id = params.fetch("user_id", "")
      state = params.fetch("state", "")

      # Check if user has given consent
      unless user_has_given_consent?(context)
        # Store the state parameter to verify later
        Authly.config.state_store.store(state)
        # Render consent page where the user can approve or deny the requested access
        render_consent_page(context, client_id, scope, state)
        return
      end

      # Verify the state parameter to prevent CSRF attacks
      unless Authly.config.state_store.valid?(state)
        ResponseHelper.write(context, 400, "text/plain", "Invalid state parameter")
        return
      end

      # Consume the state to prevent replay attacks
      Authly.config.state_store.consume(state)

      # Enforce PKCE validation if configured
      validate_pkce!(client_id, code_challenge, challenge_method)

      # Determine if JARM should be used
      use_jarm = should_use_jarm?(client_id, response_mode)

      # Handle different response types
      case response_type
      when "code"
        # Authorization Code flow
        authorization_code = Authly.code(
          response_type,
          client_id,
          redirect_uri,
          scope,
          code_challenge,
          challenge_method,
          user_id
        ).to_s

        if use_jarm
          # Use JARM to return the response as JWT
          handle_jarm_response(context, client_id, redirect_uri, response_mode, authorization_code, state)
        else
          # Standard response - redirect with code in query
          redirect_location = URI.parse(redirect_uri)
          redirect_location.query = "code=#{URI.encode_www_form(authorization_code)}&state=#{URI.encode_www_form(state)}"
          ResponseHelper.redirect(context, redirect_location.to_s)
        end
      when "token"
        # Implicit flow - return access token directly
        result = Authly.code(
          response_type,
          client_id,
          redirect_uri,
          scope,
          code_challenge,
          challenge_method,
          user_id
        )

        # For implicit flow, tokens are returned in the fragment
        if result.is_a?(AccessToken)
          if use_jarm
            # Use JARM to return the response as JWT
            handle_jarm_response(
              context,
              client_id,
              redirect_uri,
              response_mode,
              nil,
              state,
              result.access_token,
              "Bearer",
              result.expires_in,
              scope,
              result.id_token
            )
          else
            # Standard response - fragment with token
            redirect_location = URI.parse(redirect_uri)
            fragment_params = "access_token=#{result.access_token}&token_type=Bearer&expires_in=#{result.expires_in}&scope=#{URI.encode_www_form(scope)}&state=#{URI.encode_www_form(state)}"
            redirect_location.fragment = fragment_params
            ResponseHelper.redirect(context, redirect_location.to_s)
          end
        else
          raise Error.invalid_response_type
        end
      else
        raise Error.invalid_response_type
      end
    rescue e : Error
      ResponseHelper.write(context, e.code, "text/plain", e.message)
    end

    private def self.user_has_given_consent?(context)
      # Logic to determine if the user has already given consent
      # This can be done by checking session or context information
      consent = context.request.query_params["consent"]?
      consent == "approved"
    end

    private def self.render_consent_page(context, client_id, scope, state = Random::Secure.hex(32))
      # Render a simple consent page where the user can approve or deny the requested access
      ResponseHelper.write(context, 200, "text/html", <<-HTML)
        <html>
          <body>
            <h1>Authorization Request</h1>
            <p>Client ID: #{client_id}</p>
            <p>Requested Scopes: #{scope}</p>
            <form action="/authorize" method="get">
              <input type="hidden" name="client_id" value="#{client_id}">
              <input type="hidden" name="scope" value="#{scope}">
              <input type="hidden" name="state" value="#{state}">
              <input type="hidden" name="redirect_uri" value="#{context.request.query_params["redirect_uri"]}">
              <button type="submit" name="consent" value="approved">Approve</button>
              <button type="submit" name="consent" value="denied">Deny</button>
            </form>
          </body>
        </html>
      HTML
    end

    private def self.valid_state?(state)
      # Verify that the state parameter exists in the store
      Authly.config.state_store.valid?(state) == true
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

    # Load parameters from PAR store
    private def self.load_par_params(request_uri : String, query_params : HTTP::Params)
      # Fetch PAR data from store
      par_data = Authly.config.par_store.fetch(request_uri)

      unless par_data
        raise Error.invalid_request_uri
      end

      # Validate client_id if provided in query params
      query_client_id = query_params["client_id"]?
      if query_client_id && query_client_id != par_data.client_id
        raise Error.invalid_request_uri
      end

      # Consume the request_uri (single-use)
      Authly.config.par_store.consume(request_uri)

      # Convert stored params to HTTP::Params-like structure
      # Merge query params with stored params (query params for user_id, consent, etc.)
      merged_params = par_data.params.dup
      query_params.each do |key, value|
        # Allow certain parameters from query (like user_id, consent)
        # but not authorization parameters
        unless ["request_uri", "client_id"].includes?(key)
          merged_params[key] = value
        end
      end

      # Return as a wrapper that behaves like HTTP::Params
      ParamsWrapper.new(merged_params)
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
        ResponseHelper.write(context, 200, "text/html", html)
      when "jwt"
        # Direct JWT response (for JAR flows)
        ResponseHelper.write(context, 200, "application/jwt", jwt_response)
      else
        raise Error.invalid_request
      end
    end

    # Parse JWT algorithm name to JWT::Algorithm
    private def self.parse_jwt_algorithm(alg_name : String?) : JWT::Algorithm?
      return nil unless alg_name

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
      else
        nil
      end
    end
  end

  # Wrapper to make Hash behave like HTTP::Params
  class ParamsWrapper
    def initialize(@params : Hash(String, String))
    end

    def fetch(key : String, default : String)
      @params.fetch(key, default)
    end

    def [](key : String)
      @params[key]
    end

    def []?(key : String)
      @params[key]?
    end
  end
end
