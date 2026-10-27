require "base64"
require "uri"

module Authly
  # Client authentication for the endpoints a client calls with its own credentials (RFC 6749
  # section 2.3.1): HTTP Basic (`client_secret_basic`), else `client_id` and `client_secret` in the
  # form body (`client_secret_post`).
  module ClientAuthentication
    extend self

    NO_CREDENTIALS = {nil, nil}

    # The id and secret the request presents, `nil` for each one it does not.
    def credentials(context : HTTP::Server::Context) : Tuple(String?, String?)
      basic_credentials(context.request.headers["Authorization"]?) || begin
        params = context.request.form_params
        {params["client_id"]?, params["client_secret"]?}
      end
    end

    # The authenticated client's id; otherwise answers 401 `invalid_client` and returns `nil`.
    def authenticate(context : HTTP::Server::Context) : String?
      client_id, client_secret = credentials(context)
      return client_id if client_id && client_secret && Authly.clients.authorized?(client_id, client_secret)

      context.response.headers["WWW-Authenticate"] = %(Basic realm="authly")
      ResponseHelper.write(context, 401, "application/json",
        {error: "invalid_client", error_description: "Client authentication failed"}.to_json)
      nil
    end

    # `nil` without a Basic header. A Basic header that cannot be read presents no credentials at all:
    # the request has chosen its method (RFC 6749 2.3), so the form is not consulted.
    private def basic_credentials(header : String?) : Tuple(String?, String?)?
      return unless header && header.matches?(/\ABasic(\s|\z)/i)
      return NO_CREDENTIALS unless match = header.match(/\ABasic\s+(\S+)\z/i)

      id, separator, secret = Base64.decode_string(match[1]).partition(':')
      return NO_CREDENTIALS if separator.empty?
      {URI.decode_www_form(id), URI.decode_www_form(secret)}
    rescue Base64::Error | ArgumentError
      NO_CREDENTIALS
    end
  end
end
