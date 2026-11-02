require "base64"
require "json"
require "openssl/digest"
require "random/secure"
require "uri"

module Authly
  class SocialAuthHandler
    SOCIAL_STATE_PURPOSE = "social_state"

    def self.handle_start(context : HTTP::Server::Context, provider_name : String) : Nil
      provider = Authly.config.social_providers[provider_name]?
      unless provider
        ResponseHelper.write(context, 404, "application/json", {
          error:             "invalid_request",
          error_description: "Unknown social provider",
        }.to_json)
        return
      end

      query = context.request.query_params
      client_id = query.fetch("client_id", "")
      redirect_uri = query.fetch("redirect_uri", "")
      scope = query.fetch("scope", "")
      client_state = query.fetch("state", "")
      response_type = query.fetch("response_type", "code")
      oidc_nonce = query.fetch("nonce", "")

      unless client_id.empty?
        validate_oauth_client!(client_id, redirect_uri, scope, response_type)
      end

      state_nonce = Random::Secure.hex(16)
      Authly.config.state_store.store(state_nonce, Authly.config.social_state_ttl)

      code_verifier = Random::Secure.hex(32)
      code_challenge = pkce_s256_challenge(code_verifier)

      claims = {
        "provider"      => provider.name,
        "nonce"         => state_nonce,
        "code_verifier" => code_verifier,
        "client_id"     => client_id,
        "redirect_uri"  => redirect_uri,
        "scope"         => scope,
        "client_state"  => client_state,
        "response_type" => response_type,
        "oidc_nonce"    => oidc_nonce,
      }

      signed_state = FormToken.issue(SOCIAL_STATE_PURPOSE, claims, Authly.config.social_state_ttl)
      authorize_location = provider.authorize_url(
        state: signed_state,
        code_challenge: code_challenge,
        code_challenge_method: "S256",
        nonce: oidc_nonce.presence,
      )

      ResponseHelper.redirect(context, authorize_location)
    rescue e : Error
      ResponseHelper.write(context, e.code, "application/json", {
        error:             e.type.to_s,
        error_description: e.message,
      }.to_json)
    end

    def self.handle_callback(context : HTTP::Server::Context, provider_name : String) : Nil
      provider = Authly.config.social_providers[provider_name]?
      unless provider
        ResponseHelper.write(context, 404, "application/json", {
          error:             "invalid_request",
          error_description: "Unknown social provider",
        }.to_json)
        return
      end

      params = extract_callback_params(context)
      check_upstream_error!(params)
      claims = verify_callback_state!(params.fetch("state", ""), provider.name)
      profile = exchange_callback_profile(provider, params, claims)

      resolved_owner = SocialGrant.resolve_owner(profile)
      unless resolved_owner
        ResponseHelper.write(context, 403, "application/json", {
          error:             "access_denied",
          error_description: "No resource owner matched the social identity",
        }.to_json)
        return
      end

      subject = resolve_subject(resolved_owner)
      complete_authentication(context, provider, profile, subject, claims)
    rescue e : Error
      ResponseHelper.write(context, e.code, "application/json", {
        error:             e.type.to_s,
        error_description: e.message,
      }.to_json)
    end

    private def self.check_upstream_error!(params : Hash(String, String)) : Nil
      if upstream_error = params["error"]?.presence
        raise Error.access_denied if upstream_error == "access_denied"
        raise Error.invalid_grant
      end
    end

    private def self.verify_callback_state!(state_token : String, provider_name : String) : Hash(String, String)
      claims = FormToken.verify(SOCIAL_STATE_PURPOSE, state_token)
      raise Error.invalid_state unless claims
      raise Error.invalid_state unless claims["provider"]? == provider_name

      state_nonce = claims["nonce"]?
      raise Error.invalid_state unless state_nonce && Authly.config.state_store.consume(state_nonce)
      claims
    end

    private def self.exchange_callback_profile(
      provider : Social::Provider,
      params : Hash(String, String),
      claims : Hash(String, String),
    ) : SocialProfile
      code = params.fetch("code", "")
      id_token = params["id_token"]?
      extra_params = {} of String => String
      if user_json = params["user"]?
        extra_params["user"] = user_json
      end

      if !code.empty?
        provider.exchange_code(
          code: code,
          code_verifier: claims["code_verifier"]?.presence,
          extra_params: extra_params,
        )
      elsif id_token && !id_token.empty?
        provider.verify_token(id_token: id_token, extra_params: extra_params)
      else
        raise Error.invalid_request
      end
    end

    private def self.complete_authentication(
      context : HTTP::Server::Context,
      provider : Social::Provider,
      profile : SocialProfile,
      subject : String,
      claims : Hash(String, String),
    ) : Nil
      client_id = claims.fetch("client_id", "")
      redirect_uri = claims.fetch("redirect_uri", "")
      scope = claims.fetch("scope", "").presence || "read"
      client_state = claims.fetch("client_state", "")
      response_type = claims.fetch("response_type", "code")
      oidc_nonce = claims.fetch("oidc_nonce", "")

      if callback_hook = Authly.config.on_social_authenticated
        token = client_id.empty? ? nil : issue_token(client_id, scope, subject, oidc_nonce)
        callback_hook.call(context, profile, subject, token)
        return
      end

      if !client_id.empty? && !redirect_uri.empty?
        if response_type == "token"
          token = issue_token(client_id, scope, subject, oidc_nonce)
          redirect_with_params(
            context,
            redirect_uri,
            {
              "access_token" => token.access_token,
              "token_type"   => "Bearer",
              "expires_in"   => token.expires_in.to_s,
              "scope"        => scope,
              "state"        => client_state,
            },
            fragment: true,
          )
        else
          code = Authly.code("code", client_id, redirect_uri, scope, "", "", subject, oidc_nonce)
          redirect_with_params(
            context,
            redirect_uri,
            {"code" => code.to_s, "state" => client_state},
            fragment: false,
          )
        end
        return
      end

      effective_client_id = client_id.presence || "social:#{provider.name}"
      token = issue_token(effective_client_id, scope, subject, oidc_nonce)
      context.response.headers["Cache-Control"] = "no-store"
      ResponseHelper.write(context, 200, "application/json", {
        sub:           subject,
        jti:           token.jti,
        access_token:  token.access_token,
        token_type:    token.token_type,
        scope:         token.scope,
        expires_in:    token.expires_in,
        refresh_token: token.refresh_token,
        id_token:      token.id_token,
        provider:      profile.provider,
        social_uid:    profile.uid,
      }.to_json)
    end

    private def self.issue_token(
      client_id : String,
      scope : String,
      subject : String,
      nonce : String = "",
    ) : AccessToken
      id_jwt =
        if scope.split.includes?("openid")
          payload = build_id_token_payload(subject, client_id, nonce)
          Authly.jwt_encode(payload)
        end

      AccessToken.new(client_id, scope, id_jwt, nil, subject)
    end

    private def self.build_id_token_payload(
      subject : String,
      client_id : String,
      nonce : String,
    ) : Hash(String, String | Int64)
      payload =
        begin
          Authly.owners.id_token(subject)
        rescue
          {
            "user_id" => subject,
            "sub"     => subject,
            "iat"     => Time.utc.to_unix,
            "exp"     => Authly.config.access_ttl.from_now.to_unix,
            "iss"     => Authly.config.issuer,
          } of String => String | Int64
        end
      payload["nonce"] = nonce unless nonce.empty?
      payload["iss"] = Authly.config.issuer
      payload["aud"] = client_id
      payload
    end

    private def self.resolve_subject(owner_id : String) : String
      Authly.owners.id_token(owner_id)["sub"].to_s
    rescue
      owner_id
    end

    private def self.validate_oauth_client!(
      client_id : String,
      redirect_uri : String,
      scope : String,
      response_type : String,
    ) : Nil
      raise Error.invalid_client unless Authly.clients.valid_client?(client_id)
      unless redirect_uri.empty?
        raise Error.invalid_redirect_uri unless Authly.clients.valid_redirect?(client_id, redirect_uri)
      end
      unless scope.empty?
        raise Error.invalid_scope unless Authly.clients.allowed_scopes?(client_id, scope)
      end
      raise Error.invalid_response_type unless ["code", "token"].includes?(response_type)
    end

    private def self.redirect_with_params(
      context : HTTP::Server::Context,
      redirect_uri : String,
      params : Hash(String, String),
      fragment : Bool,
    ) : Nil
      location = URI.parse(redirect_uri)
      encoded = URI::Params.build do |form|
        params.each { |k, v| form.add(k, v) unless v.empty? }
      end

      if fragment
        location.fragment = encoded
      else
        location.query = [location.query.presence, encoded].compact.join("&")
      end
      ResponseHelper.redirect(context, location.to_s)
    end

    private def self.extract_callback_params(context : HTTP::Server::Context) : Hash(String, String)
      result = {} of String => String
      context.request.query_params.each { |k, v| result[k] = v }
      if context.request.method == "POST"
        context.request.form_params.each { |k, v| result[k] = v }
      end
      result
    end

    private def self.pkce_s256_challenge(verifier : String) : String
      digest = OpenSSL::Digest.new("SHA256")
      digest.update(verifier)
      Base64.urlsafe_encode(digest.final, padding: false)
    end
  end
end
