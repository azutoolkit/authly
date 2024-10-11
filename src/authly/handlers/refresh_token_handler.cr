module Authly
  class RefreshTokenHandler
    def self.handle(context : HTTP::Server::Context)
      # Extract parameters from the request
      client_id = context.request.form_params["client_id"]?
      client_secret = context.request.form_params["client_secret"]?
      refresh_token = context.request.form_params["refresh_token"]?

      # Ensure all required parameters are present
      unless client_id && client_secret && refresh_token
        ResponseHelper.write(context, 400, "application/json", {"error" => "missing_parameters"}.to_json)
        return
      end

      # Instantiate the RefreshToken service
      token = Authly.access_token("refresh_token", client_id: client_id, client_secret: client_secret)
      ResponseHelper.write(
        context,
        200,
        "application/json",
        {
          refresh_token: token.refresh_token,
          access_token:  token.access_token,
        }.to_json
      )
    rescue e : Error
      ResponseHelper.write(context, e.code, "application/json", {"error" => e.message}.to_json)
    end
  end
end
