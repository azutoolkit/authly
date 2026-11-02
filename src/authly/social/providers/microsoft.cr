require "../provider"

module Authly
  module Social
    class Microsoft < Provider
      USERINFO_URL = "https://graph.microsoft.com/oidc/userinfo"

      getter tenant : String

      def initialize(
        client_id : String,
        client_secret : String,
        redirect_uri : String,
        @tenant : String = "common",
        scopes : Array(String) = ["openid", "profile", "email", "User.Read"],
        name : String = "microsoft",
      )
        super(name, client_id, client_secret, redirect_uri, scopes)
      end

      def authorize_endpoint : String
        "https://login.microsoftonline.com/#{@tenant}/oauth2/v2.0/authorize"
      end

      def token_endpoint : String
        "https://login.microsoftonline.com/#{@tenant}/oauth2/v2.0/token"
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
            decode_jwt_payload(jwt)
          else
            raise Error.invalid_grant
          end

        uid = (claims["sub"]?.try(&.as_s?) || claims["oid"]?.try(&.as_s?) || claims["id"]?.try(&.as_s?)).presence
        raise Error.invalid_grant unless uid

        email = (claims["email"]?.try(&.as_s?) || claims["preferred_username"]?.try(&.as_s?)).presence
        verified = claims.has_key?("email_verified") ? bool_claim(claims, "email_verified") : !email.nil?

        SocialProfile.new(
          provider: @name,
          uid: uid,
          email: email,
          email_verified: verified,
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
