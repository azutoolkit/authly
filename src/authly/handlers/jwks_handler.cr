module Authly
  class JWKSHandler
    def self.handle(context)
      context.response.headers["Cache-Control"] = "public, max-age=300"
      ResponseHelper.write(context, 200, "application/jwk-set+json", JWKS.new.to_json)
    rescue ArgumentError
      ResponseHelper.write(context, 500, "application/json", {error: "server_error", error_description: "The signing key cannot be published"}.to_json)
    end
  end
end
