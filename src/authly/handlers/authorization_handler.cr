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

        # Redirect the user-agent back to the redirect_uri with the code and state
        redirect_location = URI.parse(redirect_uri)
        redirect_location.query = "code=#{URI.encode_www_form(authorization_code)}&state=#{URI.encode_www_form(state)}"
        ResponseHelper.redirect(context, redirect_location.to_s)
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
          redirect_location = URI.parse(redirect_uri)
          fragment_params = "access_token=#{result.access_token}&token_type=Bearer&expires_in=#{result.expires_in}&scope=#{URI.encode_www_form(scope)}&state=#{URI.encode_www_form(state)}"
          redirect_location.fragment = fragment_params
          ResponseHelper.redirect(context, redirect_location.to_s)
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
