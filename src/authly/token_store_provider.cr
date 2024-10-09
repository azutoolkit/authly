module Authly
  module TokenStoreProvider
    abstract def store(token : String, payload : HashToken)
    abstract def fetch(token : String) : HashToken
    abstract def revoke!(token : String)
    abstract def revoked?(token : String) : Bool
  end

  class InMemoryTokenStore
    include TokenStoreProvider
    @token_store = Hash(String, HashToken).new

    # Implement the each method to make the class enumerable
    def store(token : String, payload : HashToken)
      @token_store[token] = payload
    end

    # Method to fetch a token by its tid
    def fetch(token : String) : HashToken
      @token_store.fetch(token) { raise Error.invalid_token }
    end

    # Method to revoke a token by its jti
    def revoke!(token : String)
      @token_store.delete(token)
    end

    # Method to check if a token's jti has been revoked
    def revoked?(token : String) : Bool
      !@token_store[token].nil?
    end
  end
end
