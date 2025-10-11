module Authly
  class DiscoveryHandler
    def self.handle(context)
      base_url = Authly.config.base_url

      metadata = {
        issuer:                        base_url,
        authorization_endpoint:        "#{base_url}/oauth/authorize",
        token_endpoint:                "#{base_url}/oauth/token",
        userinfo_endpoint:             "#{base_url}/oauth/userinfo",
        jwks_uri:                      "#{base_url}/.well-known/jwks.json",
        registration_endpoint:         "#{base_url}/oauth/register",
        revocation_endpoint:           "#{base_url}/oauth/revoke",
        introspection_endpoint:        "#{base_url}/oauth/introspect",
        device_authorization_endpoint: "#{base_url}/oauth/device/code",
        scopes_supported:              ["openid", "profile", "email", "address", "phone", "offline_access"],
        response_types_supported:      ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        response_modes_supported:      ["query", "fragment"],
        grant_types_supported:         [
          "authorization_code",
          "implicit",
          "password",
          "client_credentials",
          "refresh_token",
          "urn:ietf:params:oauth:grant-type:device_code",
        ],
        subject_types_supported:               ["public"],
        id_token_signing_alg_values_supported: get_supported_algorithms,
        token_endpoint_auth_methods_supported: [
          "client_secret_basic",
          "client_secret_post",
          "none",
        ],
        code_challenge_methods_supported: get_pkce_methods,
        claims_supported:                 [
          "sub",
          "iss",
          "aud",
          "exp",
          "iat",
          "name",
          "email",
          "email_verified",
          "picture",
          "updated_at",
        ],
        request_parameter_supported:     false,
        request_uri_parameter_supported: false,
      }

      ResponseHelper.write(context, 200, "application/json", metadata.to_json)
    rescue e : Exception
      ResponseHelper.write(context, 500, "application/json", {error: "server_error", error_description: e.message}.to_json)
    end

    private def self.get_supported_algorithms : Array(String)
      # Return list of supported JWT algorithms
      [
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
      ]
    end

    private def self.get_pkce_methods : Array(String)
      methods = ["S256"]
      # Add 'plain' only if S256 is not enforced
      methods << "plain" unless Authly.config.enforce_pkce_s256
      methods
    end
  end
end
