module Authly
  # Token introspection (RFC 7662). Only an authenticated client may ask.
  class IntrospectHandler
    def self.handle(context)
      return unless ClientAuthentication.authenticate(context)

      token = context.request.form_params["token"]
      ResponseHelper.write(context, 200, "application/json", Authly.introspect(token).to_json)
    rescue e : Error
      ResponseHelper.write(context, e.code, "text/plain", e.message)
    rescue e : KeyError
      ResponseHelper.write(context, 400, "text/plain", e.message)
    end
  end
end
