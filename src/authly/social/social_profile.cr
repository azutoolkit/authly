require "json"

module Authly
  struct SocialProfile
    include JSON::Serializable

    property provider : String
    property uid : String
    property email : String? = nil
    property? email_verified : Bool = false
    property name : String? = nil
    property first_name : String? = nil
    property last_name : String? = nil
    property nickname : String? = nil
    property avatar_url : String? = nil
    property access_token : String? = nil
    property id_token : String? = nil
    property refresh_token : String? = nil
    property expires_in : Int64? = nil
    property raw_attributes : Hash(String, JSON::Any) = {} of String => JSON::Any

    def initialize(
      @provider : String,
      @uid : String,
      @email : String? = nil,
      @email_verified : Bool = false,
      @name : String? = nil,
      @first_name : String? = nil,
      @last_name : String? = nil,
      @nickname : String? = nil,
      @avatar_url : String? = nil,
      @access_token : String? = nil,
      @id_token : String? = nil,
      @refresh_token : String? = nil,
      @expires_in : Int64? = nil,
      @raw_attributes : Hash(String, JSON::Any) = {} of String => JSON::Any,
    )
    end
  end
end
