module Authly
  class JWKSHandler
    def self.handle(context)
      body = JWKS.new.to_json
      context.response.headers["Cache-Control"] = "public, max-age=300"
      ResponseHelper.write(context, 200, "application/jwk-set+json", body)
    rescue ArgumentError
      context.response.headers["Cache-Control"] = "no-store"
      ResponseHelper.write(context, 500, "application/json", {error: "server_error", error_description: "The signing key cannot be published"}.to_json)
    end
  end
end
