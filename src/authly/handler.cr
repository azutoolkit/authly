require "http/server/handler"
require "./handlers/*"

module Authly
  class Handler
    include HTTP::Handler

    def call(context)
      case context.request.path
      when "/oauth/authorize"
        return call_next(context) unless context.request.method == "GET"
        AuthorizationHandler.handle(context)
      when "/oauth/token"
        return call_next(context) unless context.request.method == "POST"
        if context.request.form_params["grant_type"] == "refresh_token"
          RefreshTokenHandler.handle(context)
        else
          AccessTokenHandler.handle(context)
        end
      when "/introspect"
        return call_next(context) unless context.request.method == "POST"
        IntrospectHandler.handle(context)
      when "/revoke"
        return call_next(context) unless context.request.method == "POST"
        RevokeHandler.handle(context)
      else
        call_next(context)
      end
    end
  end
end
