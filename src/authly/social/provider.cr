require "base64"
require "json"
require "uri"
require "./social_profile"
require "./http_client"

module Authly
  module Social
    abstract class Provider
      getter name : String
      getter client_id : String
      getter client_secret : String
      getter redirect_uri : String
      getter scopes : Array(String)

      def initialize(
        @name : String,
        @client_id : String,
        @client_secret : String,
        @redirect_uri : String,
        @scopes : Array(String),
      )
      end

      abstract def authorize_endpoint : String
      abstract def token_endpoint : String
      abstract def userinfo_endpoint : String

      def authorize_url(
        state : String,
        code_challenge : String? = nil,
        code_challenge_method : String? = "S256",
        nonce : String? = nil,
        redirect_uri : String? = nil,
        scope : String? = nil,
        extra_params : Hash(String, String) = {} of String => String,
      ) : String
        uri = URI.parse(authorize_endpoint)
        effective_redirect = redirect_uri.presence || @redirect_uri
        effective_scope = scope.presence || @scopes.join(" ")

        params = URI::Params.build do |form|
          form.add("response_type", "code")
          form.add("client_id", @client_id)
          form.add("redirect_uri", effective_redirect) unless effective_redirect.empty?
          form.add("scope", effective_scope) unless effective_scope.empty?
          form.add("state", state)
          if challenge = code_challenge.presence
            form.add("code_challenge", challenge)
            form.add("code_challenge_method", code_challenge_method.presence || "S256")
          end
          if n = nonce.presence
            form.add("nonce", n)
          end
          default_authorize_params.each do |k, v|
            form.add(k, v) unless extra_params.has_key?(k)
          end
          extra_params.each do |k, v|
            form.add(k, v)
          end
        end

        uri.query = [uri.query.presence, params].compact.join("&")
        uri.to_s
      end

      def exchange_code(
        code : String,
        redirect_uri : String? = nil,
        code_verifier : String? = nil,
        extra_params : Hash(String, String) = {} of String => String,
      ) : SocialProfile
        raise Error.invalid_request if code.empty?

        form = {
          "grant_type"    => "authorization_code",
          "code"          => code,
          "client_id"     => @client_id,
          "client_secret" => @client_secret,
          "redirect_uri"  => redirect_uri.presence || @redirect_uri,
        }
        if verifier = code_verifier.presence
          form["code_verifier"] = verifier
        end
        extra_params.each { |k, v| form[k] = v }

        headers = HTTP::Headers{"Accept" => "application/json"}
        response = http_client.post_form(token_endpoint, form, headers)
        raise Error.invalid_grant unless (200..299).includes?(response.status_code)

        token_data = parse_json_object(response.body)
        raise Error.invalid_grant if token_data.has_key?("error")

        access_token = token_data["access_token"]?.try(&.as_s?)
        id_token = token_data["id_token"]?.try(&.as_s?)
        refresh_token = token_data["refresh_token"]?.try(&.as_s?)
        expires_in = token_data["expires_in"]?.try(&.as_i64?)

        build_profile(
          access_token: access_token,
          id_token: id_token,
          refresh_token: refresh_token,
          expires_in: expires_in,
          extra_params: extra_params,
        )
      end

      def verify_token(
        access_token : String? = nil,
        id_token : String? = nil,
        extra_params : Hash(String, String) = {} of String => String,
      ) : SocialProfile
        raise Error.invalid_request if access_token.to_s.empty? && id_token.to_s.empty?

        build_profile(
          access_token: access_token.presence,
          id_token: id_token.presence,
          refresh_token: nil,
          expires_in: nil,
          extra_params: extra_params,
        )
      end

      protected def default_authorize_params : Hash(String, String)
        {} of String => String
      end

      protected abstract def build_profile(
        access_token : String?,
        id_token : String?,
        refresh_token : String?,
        expires_in : Int64?,
        extra_params : Hash(String, String),
      ) : SocialProfile

      protected def fetch_userinfo_json(access_token : String, url : String = userinfo_endpoint) : Hash(String, JSON::Any)
        headers = HTTP::Headers{
          "Authorization" => "Bearer #{access_token}",
          "Accept"        => "application/json",
        }
        response = http_client.get(url, headers)
        raise Error.invalid_grant unless (200..299).includes?(response.status_code)
        parse_json_object(response.body)
      end

      protected def parse_json_object(body : String) : Hash(String, JSON::Any)
        JSON.parse(body).as_h
      rescue JSON::ParseException | TypeCastError
        raise Error.invalid_grant
      end

      protected def decode_jwt_payload(jwt_token : String) : Hash(String, JSON::Any)
        parts = jwt_token.split('.')
        raise Error.invalid_grant unless parts.size == 3
        decoded = String.new(Base64.decode(parts[1]))
        parse_json_object(decoded)
      rescue Base64::Error | ArgumentError
        raise Error.invalid_grant
      end

      protected def verify_id_token_claims!(
        claims : Hash(String, JSON::Any),
        expected_issuers : Array(String),
      ) : Nil
        iss = claims["iss"]?.try(&.as_s?) || ""
        raise Error.invalid_grant unless expected_issuers.includes?(iss)

        aud_claim = claims["aud"]?
        aud_matches =
          if s = aud_claim.try(&.as_s?)
            s == @client_id
          elsif arr = aud_claim.try(&.as_a?)
            arr.any? { |item| item.as_s? == @client_id }
          else
            false
          end
        raise Error.invalid_grant unless aud_matches

        exp = claims["exp"]?.try(&.as_i64?)
        raise Error.invalid_grant if exp.nil? || exp <= Time.utc.to_unix
      end

      protected def bool_claim(claims : Hash(String, JSON::Any), key : String) : Bool
        val = claims[key]?
        return false unless val
        if !(b = val.as_bool?).nil?
          b
        elsif s = val.as_s?
          s.downcase == "true"
        else
          false
        end
      end

      protected def http_client : HttpClient
        Authly.config.social_http_client
      end
    end
  end
end
