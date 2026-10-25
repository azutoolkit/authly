require "http/server/handler"
require "./handlers/*"

module Authly
  class Handler
    include HTTP::Handler

    def call(context)
      handle_route(context) || call_next(context)
    end

    private def handle_route(context) : Bool
      path = context.request.path

      case path
      when "/oauth/authorize"
        handle_if_methods(context, ["GET", "POST"]) { AuthorizationHandler.handle(context) }
      when "/oauth/token"
        handle_token_endpoint(context)
      when "/oauth/par"
        handle_if_method(context, "POST") { PARHandler.handle(context) }
      when "/oauth/device/code"
        handle_if_method(context, "POST") { DeviceAuthorizationHandler.handle(context) }
      when "/device"
        handle_if_methods(context, ["GET", "POST"]) { DeviceVerificationHandler.handle(context) }
      when "/introspect"
        handle_if_method(context, "POST") { IntrospectHandler.handle(context) }
      when "/revoke"
        handle_if_method(context, "POST") { RevokeHandler.handle(context) }
      when "/oauth/userinfo"
        handle_if_method(context, "GET") { UserInfoHandler.handle(context) }
      when "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server", "/.well-known/jwks.json"
        handle_if_methods(context, ["GET", "HEAD"]) { handle_well_known(context, path) }
      when "/oauth/register"
        handle_registration_endpoint(context)
      else
        false
      end
    end

    private def handle_well_known(context, path : String) : Nil
      if path == "/.well-known/jwks.json"
        JWKSHandler.handle(context)
      else
        DiscoveryHandler.handle(context)
      end
    end

    private def handle_if_method(context, expected_method : String, &)
      return false unless context.request.method == expected_method
      yield
      true
    end

    private def handle_if_methods(context, expected_methods : Array(String), &)
      return false unless expected_methods.includes?(context.request.method)
      yield
      true
    end

    private def handle_token_endpoint(context) : Bool
      return false unless context.request.method == "POST"
      if context.request.form_params["grant_type"] == "refresh_token"
        RefreshTokenHandler.handle(context)
      else
        AccessTokenHandler.handle(context)
      end
      true
    end

    private def handle_registration_endpoint(context) : Bool
      return false unless context.request.method == "POST"
      return false unless Authly.config.allow_dynamic_registration?
      ClientRegistrationHandler.handle(context)
      true
    end
  end
end
