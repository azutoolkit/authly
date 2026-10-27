module Authly
  # Token revocation (RFC 7009). The client must authenticate, and only revokes its own tokens: a
  # token issued to another client is left alone, and the answer is the same 200, so it reveals nothing.
  class RevokeHandler
    def self.handle(context)
      unless context.request.method == "POST"
        return ResponseHelper.write(context, 405, "text/plain", "Method not allowed")
      end
      return unless client_id = ClientAuthentication.authenticate(context)

      token = context.request.form_params["token"]
      Authly.revoke(token) if TokenManager.instance.issued_to?(token, client_id)
      ResponseHelper.write(context, 200, "text/plain", "Token revoked successfully")
    rescue e : Error
      ResponseHelper.write(context, e.code, "text/plain", e.message)
    rescue e : KeyError
      ResponseHelper.write(context, 400, "text/plain", e.message)
    end
  end
end
