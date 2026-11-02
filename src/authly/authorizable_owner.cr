module Authly
  module AuthorizableOwner
    abstract def authorized?(username : String, password : String) : Bool
    abstract def id_token(user_id : String) : Hash(String, String | Int64)

    def verify_challenge_response?(
      challenge : String,
      response : String,
      identifier : String? = nil,
      username : String? = nil,
      owner_id : String? = nil,
      key_id : String? = nil,
      algorithm : String? = nil,
    ) : Bool
      false
    end

    def resolve_social_owner(profile : SocialProfile) : String?
      nil
    end
  end
end
