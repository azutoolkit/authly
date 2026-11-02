require "../provider"

module Authly
  module Social
    class GenericOAuth2 < Provider
      getter authorize_endpoint : String
      getter token_endpoint : String
      getter userinfo_endpoint : String
      getter uid_field : String
      getter email_field : String
      getter email_verified_field : String
      getter name_field : String
      getter avatar_field : String

      def initialize(
        name : String,
        client_id : String,
        client_secret : String,
        redirect_uri : String,
        @authorize_endpoint : String,
        @token_endpoint : String,
        @userinfo_endpoint : String,
        scopes : Array(String) = ["openid", "profile", "email"],
        @uid_field : String = "sub",
        @email_field : String = "email",
        @email_verified_field : String = "email_verified",
        @name_field : String = "name",
        @avatar_field : String = "picture",
      )
        super(name, client_id, client_secret, redirect_uri, scopes)
      end

      protected def build_profile(
        access_token : String?,
        id_token : String?,
        refresh_token : String?,
        expires_in : Int64?,
        extra_params : Hash(String, String),
      ) : SocialProfile
        claims =
          if token = access_token.presence
            fetch_userinfo_json(token)
          elsif jwt = id_token.presence
            decode_jwt_payload(jwt)
          else
            raise Error.invalid_grant
          end

        raw_uid = claims[@uid_field]? || claims["sub"]? || claims["id"]?
        uid = (raw_uid.try(&.as_s?) || raw_uid.try(&.as_i64?).try(&.to_s)).presence
        raise Error.invalid_grant unless uid

        SocialProfile.new(
          provider: @name,
          uid: uid,
          email: claims[@email_field]?.try(&.as_s?),
          email_verified: bool_claim(claims, @email_verified_field),
          name: claims[@name_field]?.try(&.as_s?),
          first_name: claims["given_name"]?.try(&.as_s?),
          last_name: claims["family_name"]?.try(&.as_s?),
          nickname: claims["nickname"]?.try(&.as_s?) || claims["preferred_username"]?.try(&.as_s?),
          avatar_url: claims[@avatar_field]?.try(&.as_s?),
          access_token: access_token,
          id_token: id_token,
          refresh_token: refresh_token,
          expires_in: expires_in,
          raw_attributes: claims,
        )
      end
    end
  end
end
