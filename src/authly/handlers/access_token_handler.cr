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
      )

      ResponseHelper.write(context, 200, "application/json", {"access_token" => access_token}.to_json)
    rescue e : Error
      ResponseHelper.write(context, e.code, "text/plain", e.message)
    end
  end
end
