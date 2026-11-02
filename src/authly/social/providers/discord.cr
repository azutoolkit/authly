require "../provider"

module Authly
  module Social
    class Discord < Provider
      AUTHORIZE_URL = "https://discord.com/api/oauth2/authorize"
      TOKEN_URL     = "https://discord.com/api/oauth2/token"
      USERINFO_URL  = "https://discord.com/api/users/@me"

      def initialize(
        client_id : String,
        client_secret : String,
        redirect_uri : String,
        scopes : Array(String) = ["identify", "email"],
        name : String = "discord",
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
        uid = claims["id"]?.try(&.as_s?).presence
        raise Error.invalid_grant unless uid

        username = claims["username"]?.try(&.as_s?)
        global_name = claims["global_name"]?.try(&.as_s?).presence || username
        avatar_hash = claims["avatar"]?.try(&.as_s?).presence
        avatar_url = avatar_hash ? "https://cdn.discordapp.com/avatars/#{uid}/#{avatar_hash}.png" : nil

        SocialProfile.new(
          provider: @name,
          uid: uid,
          email: claims["email"]?.try(&.as_s?),
          email_verified: bool_claim(claims, "verified"),
          name: global_name,
          nickname: username,
          avatar_url: avatar_url,
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
