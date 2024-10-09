module Authly
  # Token Management Class

  class TokenFactory
    TOKEN_PROVIDER = {
      "jwt"    => JWTToken.new,
      "opaque" => OpaqueToken.new,
    }

    def self.create : TokenStrategy
      TOKEN_PROVIDER.fetch(Authly.config.token_type) do
        raise Error.unsupported_token_type
      end
    end
  end
end
