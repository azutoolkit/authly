module Authly
  class InMemoryJTIProvider
    include Authly::JTIProvider
    include Enumerable(String)

    # Use a set to track revoked tokens by their jti
    def initialize
      @revoked_tokens = Set(String).new
    end

    # Implement the each method to make the class enumerable
    def each
      @revoked_tokens.each { |jti| yield jti }
    end

    # Method to revoke a token by its jti
    def revoke(jti : String)
      @revoked_tokens.add(jti)
    end

    # Method to check if a token's jti has been revoked
    def revoked?(jti : String) : Bool
      any? { |revoked_jti| revoked_jti == jti }
    end
  end
end
