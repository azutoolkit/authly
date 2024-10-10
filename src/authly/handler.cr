require "http/server/handler"

module Authly
  module ResponseHelper
    def self.write(context, status_code, content_type = "text/plain", body = "")
      context.response.status_code = status_code
      context.response.content_type = content_type
      context.response.print body
    end
  end

  class AuthorizationHandler
    def self.handle(context)
      params = context.request.query_params
      client_id = params.fetch("client_id", "")
      redirect_uri = params.fetch("redirect_uri", "")
      response_type = params.fetch("response_type", "")
      scope = params.fetch("scope", "")
      state = params.fetch("state", "")
      code_challenge = params.fetch("code_challenge", "")
      challenge_method = params.fetch("code_challenge_method", "")
      user_id = params.fetch("user_id", "")

      authorization_code = Authly.code(
        response_type,
        client_id,
        redirect_uri,
        scope,
        code_challenge,
        challenge_method,
        user_id).to_s

      context.response.headers["Location"] = "#{redirect_uri}?code=#{authorization_code}&state=#{state}"
      ResponseHelper.write(context, 302)
    rescue e : Error
      ResponseHelper.write(context, e.code, "text/plain", e.message)
    end
  end

  class AccessTokenHandler
    def self.handle(context)
      # Extracting request parameters
      params = context.request.form_params
      grant_type = params.fetch("grant_type", "")
      client_id = params.fetch("client_id", "")
      client_secret = params.fetch("client_secret", "")
      redirect_uri = params.fetch("redirect_uri", "")
      authorization_code = params.fetch("code", "")
      username = params.fetch("username", "")
      password = params.fetch("password", "")
      refresh_token = params.fetch("refresh_token", "")
      code = params.fetch("code", "")
      code_verifier = params.fetch("code_verifier", "")

      access_token = Authly.access_token(
        grant_type: grant_type,
        client_id: client_id,
        client_secret: client_secret,
        username: username,
        password: password,
        redirect_uri: redirect_uri,
        code: code,
        verifier: code_verifier,
        refresh_token: refresh_token,
      )

      ResponseHelper.write(context, 200, "application/json", {"access_token" => access_token}.to_json)
    rescue e : Error
      ResponseHelper.write(context, e.code, "text/plain", e.message)
    end
  end

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

  class OAuthHandler
    include HTTP::Handler

    def call(context)
      case context.request.path
      when "/oauth/authorize"
        AuthorizationHandler.handle(context)
      when "/oauth/token"
        AccessTokenHandler.handle(context)
      when "/introspect"
        IntrospectHandler.handle(context)
      when "/revoke"
        RevokeHandler.handle(context)
      else
        call_next(context)
      end
    end
  end
end
