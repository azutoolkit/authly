module Authly
  class AccessTokenHandler
    def self.handle(context)
      # Extracting request parameters
      params = context.request.form_params
      grant_type = params.fetch("grant_type", "")
      client_id = params.fetch("client_id", "")
      client_secret = params.fetch("client_secret", "")
      redirect_uri = params.fetch("redirect_uri", "")
      username = params.fetch("username", "")
      password = params.fetch("password", "")
      refresh_token = params.fetch("refresh_token", "")
      code = params.fetch("code", "")
      code_verifier = params.fetch("code_verifier", "")

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
        cert_thumbprint: cert_thumbprint,
      )

      ResponseHelper.write(context, 200, "application/json", access_token.to_json)
    rescue e : Error
      ResponseHelper.write(context, e.code, "text/plain", e.message)
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
