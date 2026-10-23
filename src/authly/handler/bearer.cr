require "http/server"
require "./challenge"
require "./path_filter"

module Authly
  class Handler
    # Protects the routes behind it with OAuth 2.0 bearer tokens (RFC 6750). It is a plain
    # `HTTP::Handler`: it needs no web framework, so it goes into any handler chain.
    #
    # It protects **every** request unless told otherwise. List what is public with `except_exact`
    # (just that path) or `except` (that path **and everything below it**, case-sensitively:
    # `except: ["/health"]` also exempts `/health/anything`). Prefer `except_exact` for a health check:
    #
    # ```
    # verifier = Authly::StrategyTokenVerifier.new(audience: "https://api.example.com")
    # bearer = Authly::Handler::Bearer.new(verifier, realm: "api", except_exact: ["/health"])
    # HTTP::Server.new([bearer, Authly::Handler::RequireScope.all("read:users"), app])
    # ```
    #
    # `prefixes:` turns that around into an allowlist (only those paths are protected, every other
    # path is open), which fails open for any route you forget to list: prefer `except`. See `PathFilter`
    # for how paths are compared.
    #
    # Set an `audience` on the verifier (and `config.access_token_audience` on the issuer): without
    # it a token minted for one API is accepted by every other API that shares the key.
    #
    # A verified token's claims are available downstream as `context.authly_claims`. Anything else
    # ends the request here: no credentials 401, a malformed header 400 `invalid_request`, a bad,
    # expired, revoked or wrongly addressed token 401 `invalid_token`, and a token store that cannot
    # be reached 503 with `Retry-After` (not 401, which would make clients re-authenticate for
    # nothing). The token is read from the `Authorization` header only, unless `allow_query_token` is
    # set (RFC 6750 section 2.3 discourages `?access_token=`: URLs end up in logs, referrers and
    # browser history; such responses get `Cache-Control: private` and `Referrer-Policy: no-referrer`),
    # and it is never logged.
    #
    # Put a CORS handler **before** this one, or browsers cannot read the 401. A CORS preflight
    # (`OPTIONS` with `Access-Control-Request-Method`) carries no credentials; `pass_preflight: true`
    # lets it through to the next handler instead of answering 401. That is decided by headers anyone
    # can forge: whatever answers `OPTIONS` behind it is public and must have no side effects. Give
    # `RequireScope` the same flag.
    class Bearer
      include HTTP::Handler

      MAX_TOKEN_BYTES = 8192
      TOKEN68         = /\A[A-Za-z0-9\-._~+\/]+=*\z/
      RETRY_AFTER     = "1"

      getter realm : String

      def initialize(
        @verifier : TokenVerifier = StrategyTokenVerifier.new,
        realm : String = "authly",
        @allow_query_token : Bool = false,
        prefixes : Array(String)? = nil,
        except : Array(String) = [] of String,
        except_exact : Array(String) = [] of String,
        @pass_preflight : Bool = false,
      )
        @realm = Handler.header_token!(realm, "realm")
        @paths = PathFilter.new(prefixes, except, except_exact)
      end

      def call(context : HTTP::Server::Context)
        context.authly_claims = nil
        return call_next(context) unless @paths.protects?(context.request.path)
        return call_next(context) if @pass_preflight && Handler.preflight?(context.request)

        keep_query_token_private(context) if @allow_query_token

        case credential = credential_from(context.request)
        in Challenge
          credential.write(context)
        in String
          authenticate(context, credential)
        end
      end

      private def keep_query_token_private(context : HTTP::Server::Context) : Nil
        return unless context.request.query_params.has_key?("access_token")

        context.response.headers["Cache-Control"] = "private"
        context.response.headers["Referrer-Policy"] = "no-referrer"
      end

      private def authenticate(context : HTTP::Server::Context, token : String) : Nil
        claims = token.bytesize <= MAX_TOKEN_BYTES ? @verifier.verify(token) : nil
        if claims
          context.authly_claims = claims
          call_next(context)
        else
          Challenge.invalid_token(@realm).write(context)
        end
      rescue VerificationUnavailable
        context.response.headers["Retry-After"] = RETRY_AFTER
        context.response.headers["Cache-Control"] = "no-store"
        ResponseHelper.write(context, 503, "application/json", {error: "temporarily_unavailable"}.to_json)
      end

      private def credential_from(request : HTTP::Request) : String | Challenge
        from_header = header_credential(request.headers.get?("Authorization"))
        return from_header if from_header.is_a?(Challenge)

        from_query = query_credential(request)
        return from_query if from_query.is_a?(Challenge)
        return Challenge.invalid_request(@realm) if from_header && from_query

        from_header || from_query || Challenge.missing(@realm)
      end

      private def query_credential(request : HTTP::Request) : (String | Challenge)?
        return unless @allow_query_token

        values = request.query_params.fetch_all("access_token")
        return if values.empty?

        values.size > 1 ? Challenge.invalid_request(@realm) : values.first
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
