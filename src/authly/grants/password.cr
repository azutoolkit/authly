module Authly
  class PasswordGrant < GrantStrategy
    getter client_id : String
    @client_secret : String
    @username : String
    @password : String

    def initialize(@client_id : String, @client_secret : String, @username : String, @password : String)
    end

    def authorized? : Bool
      validate_client!
      validate_owner!
      true
    end

    private def validate_client!
      raise Error.unauthorized_client unless client_authorized?
    end

    private def validate_owner!
      raise Error.owner_credentials unless owner_authorized?
    end

    private def client_authorized?
      Authly.clients.authorized?(@client_id, @client_secret)
    end

    private def owner_authorized?
      Authly.owners.authorized?(@username, @password)
    end
  end
end
