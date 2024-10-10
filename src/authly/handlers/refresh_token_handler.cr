module Authly
  class RefreshTokenHandler
    def self.handle(context : HTTP::Server::Context)
      # Extract parameters from the request
      client_id = context.request.params["client_id"]?
      client_secret = context.request.params["client_secret"]?
      refresh_token = context.request.params["refresh_token"]?

      # Ensure all required parameters are present
      unless client_id && client_secret && refresh_token
        ResponseHelper.write(context, 400, "application/json", {"error" => "missing_parameters"}.to_json)
        return
      end

      # Instantiate the RefreshToken service
      refresh_token_service = Authly::RefreshToken.new(client_id, client_secret, refresh_token)

      # Authorize and refresh the token
      if refresh_token_service.authorized?
        new_refresh_token = refresh_token_service.refresh_access_token
        new_access_token = Authly.access_token("refresh_token", client_id: client_id, client_secret: client_secret)

        # Respond with new tokens
        ResponseHelper.write(context, 200, "application/json", {"refresh_token" => new_refresh_token, "access_token" => new_access_token}.to_json)
      else
        # Respond with unauthorized error
        ResponseHelper.write(context, 401, "application/json", {"error" => "unauthorized_client"}.to_json)
      end
    rescue e : Error
      ResponseHelper.write(context, e.code, "application/json", {"error" => e.message}.to_json)
    end
  end
end
