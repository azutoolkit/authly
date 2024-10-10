module Authly
  class RevokeHandler
    def self.handle(context)
      unless context.request.method == "POST"
        ResponseHelper.write(context, 405, "text/plain", "Method not allowed")
      end

      # Extracting request parameters
      params = context.request.form_params
      token = params["token"]
      Authly.revoke(token)
      ResponseHelper.write(context, 200, "text/plain", "Token revoked successfully")
    rescue e : Error
      ResponseHelper.write(context, e.code, "text/plain", e.message)
    rescue e : KeyError
      ResponseHelper.write(context, 400, "text/plain", e.message)
    end
  end
end
