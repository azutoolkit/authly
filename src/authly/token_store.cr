module Authly
  module TokenStore
    abstract def store(token_id : String, payload)
    abstract def fetch(token_id : String)
    abstract def revoke(token_id : String)
    abstract def revoked?(token_id : String) : Bool
    abstract def valid?(token_id : String) : Bool
  end

  class InMemoryStore
    include Authly::TokenStore
    include Enumerable(String)

    # Use a set to track revoked tokens by their jti
    def initialize
      @revoked_tokens = Set(String).new
      @tokens = {} of String => Hash(String, String | Int64 | Bool)
    end

    # Implement the each method to make the class enumerable
    def each(&)
      @revoked_tokens.each { |jti| yield jti }
    end

    # Method to store a token by its jti
    def store(token_id : String, payload)
      @tokens[token_id] = payload
    end

    def fetch(token_id : String)
      @tokens.fetch(token_id) { raise Error.invalid_token }
    end

    # Method to revoke a token by its jti
    def revoke(token_id : String)
      @revoked_tokens.add(token_id)
    end

    # Method to check if a token's jti has been revoked
    def revoked?(token_id : String) : Bool
      @revoked_tokens.includes?(token_id)
    end

    def valid?(token_id : String) : Bool
      !revoked?(token_id)
    end
  end
end
