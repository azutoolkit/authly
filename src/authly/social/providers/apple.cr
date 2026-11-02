require "../provider"

module Authly
  module Social
    class Apple < Provider
      AUTHORIZE_URL = "https://appleid.apple.com/auth/authorize"
      TOKEN_URL     = "https://appleid.apple.com/auth/token"
      ISSUERS       = ["https://appleid.apple.com"]

      def initialize(
        client_id : String,
        client_secret : String,
        redirect_uri : String,
        scopes : Array(String) = ["name", "email"],
        name : String = "apple",
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
        ""
      end

      protected def default_authorize_params : Hash(String, String)
        return {} of String => String if @scopes.empty?
        {"response_mode" => "form_post"}
      end

      protected def build_profile(
        access_token : String?,
        id_token : String?,
        refresh_token : String?,
        expires_in : Int64?,
        extra_params : Hash(String, String),
      ) : SocialProfile
        jwt = id_token.presence
        raise Error.invalid_grant unless jwt

        claims = decode_jwt_payload(jwt)
        verify_id_token_claims!(claims, ISSUERS)

        uid = claims["sub"]?.try(&.as_s?).presence
        raise Error.invalid_grant unless uid

        first_name, last_name, full_name, user_email = parse_apple_user_json(extra_params["user"]?)
        email = claims["email"]?.try(&.as_s?).presence || user_email

        SocialProfile.new(
          provider: @name,
          uid: uid,
          email: email,
          email_verified: bool_claim(claims, "email_verified"),
          name: full_name,
          first_name: first_name,
          last_name: last_name,
          access_token: access_token,
          id_token: id_token,
          refresh_token: refresh_token,
          expires_in: expires_in,
          raw_attributes: claims,
        )
      end

      private def parse_apple_user_json(user_json : String?) : Tuple(String?, String?, String?, String?)
        return {nil, nil, nil, nil} if user_json.nil? || user_json.empty?

        data = JSON.parse(user_json).as_h?
        return {nil, nil, nil, nil} unless data

        name_obj = data["name"]?.try(&.as_h?)
        first = name_obj.try(&.["firstName"]?.try(&.as_s?)).presence
        last = name_obj.try(&.["lastName"]?.try(&.as_s?)).presence
        full = [first, last].compact.join(" ").presence
        email = data["email"]?.try(&.as_s?).presence

        {first, last, full, email}
      rescue JSON::ParseException | TypeCastError
        {nil, nil, nil, nil}
      end
    end
  end
end
