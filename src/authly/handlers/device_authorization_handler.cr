module Authly
  class DeviceAuthorizationHandler
    def self.handle(context)
      # Extract parameters from the request
      params = context.request.form_params
      client_id = params["client_id"]?
      scope = params.fetch("scope", "read")

      # Check if client_id is missing
      if !client_id || client_id.empty?
        ResponseHelper.write(context, 400, "application/json", {
          "error"             => "invalid_request",
          "error_description" => "Missing required parameter: client_id",
        }.to_json)
        return
      end

      # Validate client
      unless Authly.clients.any? { |client| client.id == client_id }
        ResponseHelper.write(context, 401, "application/json", {
          "error"             => "invalid_client",
          "error_description" => "Client authentication failed",
        }.to_json)
        return
      end

      # Create device authorization
      device_data = DeviceCode.create_device_authorization(client_id, scope)

      # Return device authorization response
      verification_uri = "#{Authly.config.issuer}/device"
      response = {
        "device_code"               => device_data.device_code,
        "user_code"                 => device_data.user_code,
        "verification_uri"          => verification_uri,
        "verification_uri_complete" => "#{verification_uri}?user_code=#{device_data.user_code}",
        "expires_in"                => 900, # 15 minutes
        "interval"                  => device_data.interval,
      }

      ResponseHelper.write(context, 200, "application/json", response.to_json)
    rescue e : Error
      ResponseHelper.write(context, e.code, "application/json", {
        "error"             => e.type.to_s,
        "error_description" => e.message,
      }.to_json)
    rescue e : KeyError
      ResponseHelper.write(context, 400, "application/json", {
        "error"             => "invalid_request",
        "error_description" => e.message,
      }.to_json)
    end
  end
end
