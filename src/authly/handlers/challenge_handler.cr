module Authly
  class ChallengeHandler
    def self.handle(context : HTTP::Server::Context) : Nil
      params = extract_params(context)
      basic_id, basic_secret = ClientAuthentication.credentials(context)

      client_id = basic_id.presence || params["client_id"]?.try(&.presence)
      client_secret = basic_secret.presence || params["client_secret"]?.try(&.presence)

      raise Error.invalid_request unless client_id

      if context.request.headers["Authorization"]?.try(&.matches?(/\ABasic(\s|\z)/i)) || client_secret
        raise Error.invalid_client unless client_secret && Authly.clients.authorized?(client_id, client_secret)
      else
        raise Error.invalid_client unless Authly.clients.valid_client?(client_id)
      end

      unless Authly.clients.allowed_grant_type?(client_id, "challenge_response") ||
             Authly.clients.allowed_grant_type?(client_id, "urn:ietf:params:oauth:grant-type:challenge")
        raise Error.unauthorized_client
      end

      username = params["username"]?.try(&.presence)
      owner_id = params["owner_id"]?.try(&.presence)
      key_id = params["key_id"]?.try(&.presence)

      challenge_data = ChallengeResponse.create_challenge(
        client_id: client_id,
        username: username,
        owner_id: owner_id,
        key_id: key_id,
      )

      response = {
        challenge_id: challenge_data.challenge_id,
        challenge:    challenge_data.challenge,
        expires_in:   Authly.config.challenge_ttl.total_seconds.to_i,
      }

      context.response.headers["Cache-Control"] = "no-store"
      ResponseHelper.write(context, 200, "application/json", response.to_json)
    rescue e : Error
      ResponseHelper.write(context, e.code, "application/json", {
        error:             e.type.to_s,
        error_description: e.message,
      }.to_json)
    end

    private def self.extract_params(context : HTTP::Server::Context) : Hash(String, String)
      result = Hash(String, String).new
      content_type = context.request.headers["Content-Type"]? || ""

      if content_type.includes?("application/json")
        begin
          if body = context.request.body.try(&.gets_to_end)
            if parsed = JSON.parse(body).as_h?
              parsed.each do |k, v|
                if str = v.as_s?
                  result[k] = str
                end
              end
            end
          end
        rescue JSON::ParseException
        end
      else
        context.request.form_params.each do |k, v|
          result[k] = v
        end
      end

      result
    end
  end
end
