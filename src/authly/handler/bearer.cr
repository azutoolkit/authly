require "http/server"
require "./challenge"

module Authly
  class Handler
    # Protects the routes behind it with OAuth 2.0 bearer tokens (RFC 6750). It is a plain
    # `HTTP::Handler`: it needs no web framework, so it goes into any handler chain.
    #
    # ```
    # verifier = Authly::StrategyTokenVerifier.new(audience: "https://api.example.com")
    # bearer = Authly::Handler::Bearer.new(verifier, realm: "api")
    # HTTP::Server.new([bearer, Authly::Handler::RequireScope.all("read:users"), app])
    # ```
    #
    # A verified token's claims are available downstream as `context.authly_claims`. Anything else
    # ends the request here: no credentials 401, a malformed header 400 `invalid_request`, a bad,
    # expired, revoked or wrongly addressed token 401 `invalid_token`. The token is read from the
    # `Authorization` header only, unless `allow_query_token` is set (RFC 6750 section 2.3 discourages
    # `?access_token=`: URLs end up in logs), and it is never logged.
    class Bearer
      include HTTP::Handler
      include PathPrefixes

      MAX_TOKEN_BYTES = 8192
      TOKEN68         = /\A[A-Za-z0-9\-._~+\/]+=*\z/

      getter realm : String

      def initialize(
        @verifier : TokenVerifier = StrategyTokenVerifier.new,
        realm : String = "authly",
        @allow_query_token : Bool = false,
        @prefixes : Array(String)? = nil,
      )
        @realm = Handler.header_token!(realm, "realm")
      end

      def call(context : HTTP::Server::Context)
        context.authly_claims = nil
        return call_next(context) unless covers?(context.request.path)

        case credential = credential_from(context.request)
        in Challenge
          credential.write(context)
        in String
          authenticate(context, credential)
        end
      end

      private def authenticate(context : HTTP::Server::Context, token : String) : Nil
        claims = token.bytesize <= MAX_TOKEN_BYTES ? @verifier.verify(token) : nil
        if claims
          context.authly_claims = claims
          call_next(context)
        else
          Challenge.invalid_token(@realm).write(context)
        end
      end

      private def credential_from(request : HTTP::Request) : String | Challenge
        from_header = header_credential(request.headers.get?("Authorization"))
        return from_header if from_header.is_a?(Challenge)

        from_query = @allow_query_token ? request.query_params["access_token"]? : nil
        return Challenge.invalid_request(@realm) if from_header && from_query

        from_header || from_query || Challenge.missing(@realm)
      end

      private def header_credential(values : Array(String)?) : (String | Challenge)?
        return if values.nil?
        return Challenge.invalid_request(@realm) if values.size > 1

        scheme, separator, rest = values.first.partition(' ')
        return Challenge.missing(@realm) unless scheme.compare("Bearer", case_insensitive: true) == 0

        token = rest.lstrip(' ')
        separator.empty? || !token.matches?(TOKEN68) ? Challenge.invalid_request(@realm) : token
      end
    end
  end
end
