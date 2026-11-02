module Authly
  module AuthorizableOwner
    abstract def authorized?(username : String, password : String) : Bool
    abstract def id_token(user_id : String) : Hash(String, String | Int64)
  end

  module AuthorizableClient
    abstract def valid_redirect?(client_id : String, redirect_uri : String) : Bool
    abstract def authorized?(client_id : String, client_secret : String)
    abstract def allowed_scopes?(client_id : String, scopes : String) : Bool

    # JARM (JWT Secured Authorization Response Mode) methods
    def jarm_required?(client_id : String) : Bool
      false
    end

    def jarm_signing_algorithm(client_id : String) : String?
      nil
    end

    def jarm_encryption_algorithm(client_id : String) : String?
      nil
    end

    def jarm_encryption_encoding(client_id : String) : String?
      nil
    end

    def client_public_key(client_id : String) : String?
      nil
    end

    def valid_client?(client_id : String) : Bool
      false
    end

    def verify_challenge_response?(
      challenge : String,
      response : String,
      client_id : String = "",
      key_id : String? = nil,
      algorithm : String? = nil,
    ) : Bool
      false
    end
  end
end
