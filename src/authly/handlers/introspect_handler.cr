module Authly
  class IntrospectHandler
    def self.handle(context)
      if context.request.method == "POST"
        # Extracting request parameters
        params = context.request.form_params
        token = params["token"]
        introspection_result = Authly.introspect(token)
        ResponseHelper.write(context, 200, "application/json", introspection_result.to_json)
      else
      end
    rescue e : Error
      ResponseHelper.write(context, e.code, "text/plain", e.message)
    rescue e : KeyError
      ResponseHelper.write(context, 400, "text/plain", e.message)
    end
  end
end
