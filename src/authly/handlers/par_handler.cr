module Authly
  class PARHandler
    IGNORED_PARAMS = ["user_id", "consent", "client_secret"]

    def self.handle(context)
      # Extract and authenticate client
      client_id, client_secret = ClientAuthentication.credentials(context)

      unless client_id && client_secret
        ResponseHelper.write(context, 400, "application/json", {
          error:             "invalid_client",
          error_description: "Client authentication required",
        }.to_json)
        return
      end

      # Authenticate the client
      unless Authly.clients.authorized?(client_id, client_secret)
        ResponseHelper.write(context, 401, "application/json", {
          error:             "invalid_client",
          error_description: "Client authentication failed",
        }.to_json)
        return
      end

      # Extract authorization parameters from the request body
      params = context.request.form_params

      # Validate required parameters
      response_type = params["response_type"]?
      redirect_uri = params["redirect_uri"]?

      unless response_type
        ResponseHelper.write(context, 400, "application/json", {
          error:             "invalid_request",
          error_description: "Missing required parameter: response_type",
        }.to_json)
        return
      end

      unless redirect_uri
        ResponseHelper.write(context, 400, "application/json", {
          error:             "invalid_request",
          error_description: "Missing required parameter: redirect_uri",
        }.to_json)
        return
      end

      # Validate redirect URI
      unless Authly.clients.valid_redirect?(client_id, redirect_uri)
        ResponseHelper.write(context, 400, "application/json", {
          error:             "invalid_request",
          error_description: "Invalid redirect_uri",
        }.to_json)
        return
      end

      # Validate response type
      unless ["code", "token"].includes?(response_type)
        ResponseHelper.write(context, 400, "application/json", {
          error:             "invalid_request",
          error_description: "Unsupported response_type",
        }.to_json)
        return
      end

      # Build parameter hash to store
      stored_params = Hash(String, String).new

      # Store all authorization parameters
      # `user_id` and `consent` are never taken from a request; the authorization endpoint ignores them
      # and a client has no business pushing them.
      params.each do |key, value|
        next if IGNORED_PARAMS.includes?(key)
        stored_params[key] = value
      end

      # Ensure client_id is stored
      stored_params["client_id"] = client_id

      # Generate unique request_uri
      request_uri = generate_request_uri

      # Store the PAR data
      ttl = Authly.config.par_ttl
      Authly.config.par_store.store(request_uri, stored_params, client_id, ttl)

      # Return the request_uri and expiration
      response = {
        request_uri: request_uri,
        expires_in:  ttl.total_seconds.to_i,
      }

      ResponseHelper.write(context, 201, "application/json", response.to_json)
    rescue e : Error
      ResponseHelper.write(context, e.code, "application/json", {
        error:             e.type.to_s,
        error_description: e.message,
      }.to_json)
    rescue e : Exception
      ResponseHelper.write(context, 500, "application/json", {
        error:             "server_error",
        error_description: e.message,
      }.to_json)
    end

    # Generate a unique request_uri following RFC 9126 format
    private def self.generate_request_uri : String
      random_part = Random::Secure.hex(16)
      "urn:ietf:params:oauth:request_uri:#{random_part}"
    end
  end
end
