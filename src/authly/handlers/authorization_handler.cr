require "http/server/handler"
require "uri"

module Authly
  class AuthorizationHandler
    STATE_STORE = Authly.config.state_store

    def self.handle(context)
      params = context.request.query_params
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
        STATE_STORE.store(state)
        # Render consent page where the user can approve or deny the requested access
        render_consent_page(context, client_id, scope, state)
        return
      end

      # Verify the state parameter to prevent CSRF attacks
      unless STATE_STORE.valid?(state)
        ResponseHelper.write(context, 400, "text/plain", "Invalid state parameter")
        return
      end

      # Generate authorization code after user consent
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
      redirect_location.query = URI.encode_path("code=#{authorization_code}&state=#{state}")
      ResponseHelper.redirect(context, redirect_location.to_s)
    rescue e : Error
      ResponseHelper.write(context, e.code, "text/plain", e.message)
    end

    private def self.user_has_given_consent?(context)
      # Logic to determine if the user has already given consent
      # This can be done by checking session or context information
      consent = context.request.query_params["consent"]?
      consent == "approved"
    end

    private def self.render_consent_page(context, client_id, scope, state = SecureRandom.hex(32))
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
      STATE_STORE.valid?(state) == true
    end
  end
end
