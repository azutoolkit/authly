require "../provider"

module Authly
  module Social
    class Google < Provider
      AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
      TOKEN_URL     = "https://oauth2.googleapis.com/token"
      USERINFO_URL  = "https://openidconnect.googleapis.com/v1/userinfo"
      ISSUERS       = ["https://accounts.google.com", "accounts.google.com"]

      def initialize(
        client_id : String,
        client_secret : String,
        redirect_uri : String,
        scopes : Array(String) = ["openid", "email", "profile"],
        name : String = "google",
      )
        super(name, client_id, client_secret, redirect_uri, scopes)
      end

      def authorize_endpoint : String
        AUTHORIZE_URL
      end

      def token_endpoint : String
        TOKEN_URL
      end

      def userinfo_endpoint : String
        USERINFO_URL
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
            decoded = decode_jwt_payload(jwt)
            verify_id_token_claims!(decoded, ISSUERS)
            decoded
          else
            raise Error.invalid_grant
          end

        uid = claims["sub"]?.try(&.as_s?).presence || claims["id"]?.try(&.as_s?).presence
        raise Error.invalid_grant unless uid

        SocialProfile.new(
          provider: @name,
          uid: uid,
          email: claims["email"]?.try(&.as_s?),
          email_verified: bool_claim(claims, "email_verified"),
          name: claims["name"]?.try(&.as_s?),
          first_name: claims["given_name"]?.try(&.as_s?),
          last_name: claims["family_name"]?.try(&.as_s?),
          avatar_url: claims["picture"]?.try(&.as_s?),
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
