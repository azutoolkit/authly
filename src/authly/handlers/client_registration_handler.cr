require "json"

module Authly
  class ClientRegistrationHandler
    def self.handle(context)
      # Check if dynamic registration is enabled
      unless Authly.config.allow_dynamic_registration
        ResponseHelper.write(context, 403, "application/json", {
          error:             "access_denied",
          error_description: "Dynamic client registration is not enabled",
        }.to_json)
        return
      end

      # Parse the registration request
      body = context.request.body.try(&.gets_to_end) || ""

      if body.empty?
        ResponseHelper.write(context, 400, "application/json", {
          error:             "invalid_request",
          error_description: "Request body is required",
        }.to_json)
        return
      end

      begin
        params = JSON.parse(body).as_h
      rescue e : JSON::ParseException
        ResponseHelper.write(context, 400, "application/json", {
          error:             "invalid_request",
          error_description: "Invalid JSON in request body",
        }.to_json)
        return
      end

      # Validate required fields
      unless params["redirect_uris"]?
        ResponseHelper.write(context, 400, "application/json", {
          error:             "invalid_request",
          error_description: "redirect_uris is required",
        }.to_json)
        return
      end

      # Create the dynamic client
      begin
        client = DynamicClient.from_registration_request(params)

        unless client.valid?
          ResponseHelper.write(context, 400, "application/json", {
            error:             "invalid_client_metadata",
            error_description: "Client metadata validation failed",
          }.to_json)
          return
        end

        # Store the client
        client_store = Authly.config.client_store
        unless client_store.store(client)
          ResponseHelper.write(context, 500, "application/json", {
            error:             "server_error",
            error_description: "Failed to store client registration",
          }.to_json)
          return
        end

        # Return the registered client information
        ResponseHelper.write(context, 201, "application/json", client.to_json)
      rescue e : Error
        ResponseHelper.write(context, e.code, "application/json", {
          error:             e.type.to_s,
          error_description: e.message,
        }.to_json)
      rescue e : Exception
        ResponseHelper.write(context, 400, "application/json", {
          error:             "invalid_client_metadata",
          error_description: e.message,
        }.to_json)
      end
    end
  end
end
