module Authly
  class AccessTokenHandler
    def self.handle(context)
      # Extracting request parameters
      params = context.request.form_params
      grant_type = params.fetch("grant_type", "")
      raise Error.unsupported_grant_type unless Authly.config.grant_types.includes?(grant_type)
      client_id = authenticate_client(context, grant_type)
      return unless client_id
      _, client_secret = ClientAuthentication.credentials(context)
      redirect_uri = params.fetch("redirect_uri", "")
      username = params.fetch("username", "")
      password = params.fetch("password", "")
      refresh_token = params.fetch("refresh_token", "")
      code = params.fetch("code", "")
      code_verifier = params.fetch("code_verifier", "")
      device_code = params.fetch("device_code", "")
      challenge_id = params.fetch("challenge_id", "")
      response = params.fetch("response", "")
      key_id = params["key_id"]?
      algorithm = params["algorithm"]?
      scope = params["scope"]?

      # Extract certificate thumbprint for mTLS binding
      cert_thumbprint = extract_certificate_thumbprint(context)

      access_token = Authly.access_token(
        grant_type: grant_type,
        client_id: client_id,
        client_secret: client_secret,
        username: username,
        password: password,
        redirect_uri: redirect_uri,
        code: code,
        verifier: code_verifier,
        refresh_token: refresh_token,
        device_code: device_code,
        challenge_id: challenge_id,
        response: response,
        key_id: key_id,
        algorithm: algorithm,
        scope: scope,
        cert_thumbprint: cert_thumbprint,
        options: Authly.config.issuance_options.try(&.call(client_id, grant_type)),
      )

      context.response.headers["Cache-Control"] = "no-store"
      ResponseHelper.write(context, 200, "application/json", access_token.to_json)
    rescue e : Error
      ResponseHelper.write(context, e.code, "application/json", {error: e.type.to_s}.to_json)
    end

    private def self.authenticate_client(context : HTTP::Server::Context, grant_type : String) : String?
      if ChallengeResponse::GRANT_TYPES.includes?(grant_type)
        has_basic = context.request.headers["Authorization"]?.try(&.matches?(/\ABasic(\s|\z)/i)) || false
        client_id, client_secret = ClientAuthentication.credentials(context)
        if has_basic || client_secret
          return ClientAuthentication.authenticate(context)
        end

        raise Error.invalid_request if client_id.nil? || client_id.empty?
        return client_id if Authly.clients.valid_client?(client_id)

        context.response.headers["WWW-Authenticate"] = %(Basic realm="authly")
        ResponseHelper.write(context, 401, "application/json",
          {error: "invalid_client", error_description: "Client authentication failed"}.to_json)
        return
      end

      ClientAuthentication.authenticate(context)
    end

    private def self.extract_certificate_thumbprint(context : HTTP::Server::Context) : String?
      return unless Authly.config.require_certificate_bound_tokens?

      # Extract client certificate from TLS context
      certificate = CertificateValidator.extract_certificate(context)
      return unless certificate

      # Validate certificate if trusted CAs are configured
      unless CertificateValidator.valid_certificate?(certificate, Authly.config.trusted_ca_certificates)
        return
      end

      # Calculate and return thumbprint
      CertificateValidator.calculate_thumbprint(certificate)
    end
  end
end
