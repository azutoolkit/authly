module Authly
  class UserInfoHandler
    def self.handle(context)
      # Extract access token from Authorization header
      auth_header = context.request.headers["Authorization"]?

      unless auth_header
        ResponseHelper.write(context, 401, "application/json", {
          error:             "invalid_token",
          error_description: "Authorization header is missing",
        }.to_json)
        return
      end

      # Parse Bearer token
      token_match = auth_header.match(/^Bearer (.+)$/i)
      unless token_match
        ResponseHelper.write(context, 401, "application/json", {
          error:             "invalid_token",
          error_description: "Invalid Authorization header format",
        }.to_json)
        return
      end

      access_token = token_match[1]

      # Validate and decode the token
      token_data = validate_token(access_token)
      unless token_data
        ResponseHelper.write(context, 401, "application/json", {
          error:             "invalid_token",
          error_description: "Token is invalid or expired",
        }.to_json)
        return
      end

      # Extract user information based on scope
      user_info = extract_user_info(token_data)

      ResponseHelper.write(context, 200, "application/json", user_info.to_json)
    rescue e : Error
      ResponseHelper.write(context, e.code, "application/json", {
        error:             e.type.to_s,
        error_description: e.message,
      }.to_json)
    rescue e : Exception
      ResponseHelper.write(context, 500, "application/json", {
        error:             "server_error",
        error_description: e.message,
      }.to_json)
    end

    private def self.validate_token(token : String)
      # Check if token is valid
      return unless Authly.valid?(token)

      claims = token_claims(token)
      # Refresh tokens and authorization codes are signed with the same key but are not access tokens
      claims if claims && claims["token_type"]?.try(&.as_s?) == "access_token"
    rescue
      nil
    end

    private def self.token_claims(token : String)
      # For JWT tokens, decode them
      if Authly.config.token_strategy == :jwt
        payload, _ = Authly.jwt_decode(token)
        return payload
      end

      # For opaque tokens, fetch from store
      if Authly.config.token_strategy == :opaque
        token_meta = Authly.config.token_store.fetch(token)
        return convert_to_json_any(token_meta) if token_meta
      end

      nil
    rescue
      nil
    end

    private def self.convert_to_json_any(hash : Hash)
      result = {} of String => JSON::Any
      hash.each do |key, value|
        case value
        when String
          result[key.to_s] = JSON::Any.new(value)
        when Int64
          result[key.to_s] = JSON::Any.new(value)
        when Float64
          result[key.to_s] = JSON::Any.new(value)
        when Bool
          result[key.to_s] = JSON::Any.new(value)
        else
          result[key.to_s] = JSON::Any.new(value.to_s)
        end
      end
      result
    end

    private def self.extract_user_info(token_data)
      user_info = {} of String => (JSON::Any | String | Int64 | Bool)

      # Always include 'sub' claim
      if sub = token_data["sub"]?
        user_info["sub"] = sub.as_s
      elsif sub = token_data["user_id"]?
        user_info["sub"] = sub.as_s
      end

      # Extract scope to determine which claims to include
      scope = token_data["scope"]?.try(&.as_s) || ""
      scopes = scope.split(" ")

      # Profile scope claims
      if scopes.includes?("profile") || scopes.includes?("openid")
        add_claim(user_info, token_data, "name")
        add_claim(user_info, token_data, "given_name")
        add_claim(user_info, token_data, "family_name")
        add_claim(user_info, token_data, "middle_name")
        add_claim(user_info, token_data, "nickname")
        add_claim(user_info, token_data, "preferred_username")
        add_claim(user_info, token_data, "profile")
        add_claim(user_info, token_data, "picture")
        add_claim(user_info, token_data, "website")
        add_claim(user_info, token_data, "gender")
        add_claim(user_info, token_data, "birthdate")
        add_claim(user_info, token_data, "zoneinfo")
        add_claim(user_info, token_data, "locale")
        add_claim(user_info, token_data, "updated_at")
      end

      # Email scope claims
      if scopes.includes?("email") || scopes.includes?("openid")
        add_claim(user_info, token_data, "email")
        add_claim(user_info, token_data, "email_verified")
      end

      # Address scope claims
      if scopes.includes?("address")
        add_claim(user_info, token_data, "address")
      end

      # Phone scope claims
      if scopes.includes?("phone")
        add_claim(user_info, token_data, "phone_number")
        add_claim(user_info, token_data, "phone_number_verified")
      end

      user_info
    end

    private def self.add_claim(user_info : Hash, token_data, claim : String)
      if value = token_data[claim]?
        case value.raw
        when String
          user_info[claim] = value.as_s
        when Int64
          user_info[claim] = value.as_i64
        when Bool
          user_info[claim] = value.as_bool
        else
          user_info[claim] = value
        end
      end
    end
  end
end
