module Authly
  # Token Management Class
  class TokenManager
    @token_provider : TokenProvider

    TOKEN_PROVIDER = {
      "jwt" => JWTTokenProvider.new,
      "opaque" => OpaqueTokenProvider.new
    }

    def initialize
      @token_provider = TOKEN_PROVIDER.fetch(Authly.config.token_type) do
        raise Error.unsupported_token_type
      end
    end

    def encode(payload) : String
      @token_provider.encode(payload)
    end

    def decode(token : String)
      @token_provider.decode(token)
    end

    def valid?(token : String) : Bool
      @token_provider.valid?(token)
    end

    def revoke(token : String)
      @token_provider.revoke(token)
    end

    def revoke?(token : String) : Bool
      @token_provider.revoke?(token)
    end

    def introspect(token : String)
      @token_provider.introspect(token)
    end
  end
end
