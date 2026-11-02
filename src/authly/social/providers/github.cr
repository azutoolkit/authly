require "../provider"

module Authly
  module Social
    class GitHub < Provider
      AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
      TOKEN_URL     = "https://github.com/login/oauth/access_token"
      USERINFO_URL  = "https://api.github.com/user"
      EMAILS_URL    = "https://api.github.com/user/emails"

      def initialize(
        client_id : String,
        client_secret : String,
        redirect_uri : String,
        scopes : Array(String) = ["read:user", "user:email"],
        name : String = "github",
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
        token = access_token.presence
        raise Error.invalid_grant unless token

        claims = fetch_userinfo_json(token)
        uid = (claims["id"]?.try(&.as_i64?).try(&.to_s) || claims["id"]?.try(&.as_s?)).presence
        raise Error.invalid_grant unless uid

        email = claims["email"]?.try(&.as_s?).presence
        email_verified = false

        if @scopes.includes?("user:email")
          resolved_email, verified = fetch_primary_email(token, email)
          email ||= resolved_email
          email_verified = verified
        end

        SocialProfile.new(
          provider: @name,
          uid: uid,
          email: email,
          email_verified: email_verified,
          name: claims["name"]?.try(&.as_s?),
          nickname: claims["login"]?.try(&.as_s?),
          avatar_url: claims["avatar_url"]?.try(&.as_s?),
          access_token: access_token,
          id_token: id_token,
          refresh_token: refresh_token,
          expires_in: expires_in,
          raw_attributes: claims,
        )
      end

      private def fetch_primary_email(access_token : String, current_email : String?) : Tuple(String?, Bool)
        headers = HTTP::Headers{
          "Authorization" => "Bearer #{access_token}",
          "Accept"        => "application/json",
        }
        response = http_client.get(EMAILS_URL, headers)
        return {current_email, false} unless (200..299).includes?(response.status_code)

        entries = JSON.parse(response.body).as_a?
        return {current_email, false} unless entries

        primary_entry = entries.find do |item|
          obj = item.as_h?
          obj && obj["primary"]?.try(&.as_bool?) == true
        end || entries.first?

        if obj = primary_entry.try(&.as_h?)
          addr = obj["email"]?.try(&.as_s?).presence || current_email
          verified = obj["verified"]?.try(&.as_bool?) || false
          {addr, verified}
        else
          {current_email, false}
        end
      rescue JSON::ParseException | TypeCastError
        {current_email, false}
      end
    end
  end
end
