module Authly
  class DiscoveryHandler
    def self.handle(context)
      base_url = Authly.config.base_url

      metadata = {
        issuer:                                Authly.config.issuer,
        authorization_endpoint:                "#{base_url}/oauth/authorize",
        token_endpoint:                        "#{base_url}/oauth/token",
        userinfo_endpoint:                     "#{base_url}/oauth/userinfo",
        jwks_uri:                              "#{base_url}/.well-known/jwks.json",
        registration_endpoint:                 "#{base_url}/oauth/register",
        revocation_endpoint:                   "#{base_url}/oauth/revoke",
        introspection_endpoint:                "#{base_url}/oauth/introspect",
        device_authorization_endpoint:         "#{base_url}/oauth/device/code",
        pushed_authorization_request_endpoint: "#{base_url}/oauth/par",
        scopes_supported:                      ["openid", "profile", "email", "address", "phone", "offline_access"],
        response_types_supported:              Authly.config.grant_types.includes?("implicit") ? ["code", "token"] : ["code"],
        response_modes_supported:              ["query", "fragment", "form_post", "query.jwt", "fragment.jwt", "form_post.jwt", "jwt"],
        grant_types_supported:                 Authly.config.grant_types,
        subject_types_supported:               ["public"],
        id_token_signing_alg_values_supported: supported_algorithms,
        token_endpoint_auth_methods_supported: [
          "client_secret_basic",
          "client_secret_post",
        ],
        code_challenge_methods_supported: pkce_methods,
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
        request_parameter_supported:                   false,
        request_uri_parameter_supported:               true,
        require_pushed_authorization_requests:         Authly.config.require_par?,
        authorization_signing_alg_values_supported:    jarm_signing_algorithms,
        authorization_encryption_alg_values_supported: jarm_encryption_algorithms,
        authorization_encryption_enc_values_supported: jarm_encryption_encodings,
      }

      ResponseHelper.write(context, 200, "application/json", metadata.to_json)
    rescue e : Exception
      ResponseHelper.write(context, 500, "application/json", {error: "server_error", error_description: e.message}.to_json)
    end

    private def self.supported_algorithms : Array(String)
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

    private def self.pkce_methods : Array(String)
      methods = ["S256"]
      # Add 'plain' only if S256 is not enforced
      methods << "plain" unless Authly.config.enforce_pkce_s256?
      methods
    end

    private def self.jarm_signing_algorithms : Array(String)
      # Return list of supported JARM signing algorithms
      [
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "HS256",
        "HS384",
        "HS512",
        "PS256",
        "PS384",
        "PS512",
      ]
    end

    private def self.jarm_encryption_algorithms : Array(String)
      # Return list of supported JARM encryption algorithms
      [
        "RSA-OAEP",
        "RSA-OAEP-256",
        "ECDH-ES",
        "ECDH-ES+A128KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A256KW",
      ]
    end

    private def self.jarm_encryption_encodings : Array(String)
      # Return list of supported JARM encryption encodings
      [
        "A128GCM",
        "A192GCM",
        "A256GCM",
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
      ]
    end
  end
end
