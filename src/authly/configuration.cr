require "http/server"

module Authly
  # Resolves the signed-in resource owner of a request: the subject id, or nil when nobody is signed in.
  alias OwnerAuthenticator = Proc(HTTP::Server::Context, String?)

  # Where to send a request that has no signed-in resource owner, e.g. the host's login page.
  alias LoginRedirect = Proc(HTTP::Server::Context, String)

  # The address (or other identity) a request counts as for rate limits; nil when unknown.
  alias AttemptSource = Proc(HTTP::Server::Context, String?)

  alias RegistrationAuthenticator = Proc(HTTP::Server::Context, Bool)

  class Configuration
    # The authorization endpoint (`/oauth/authorize`) and the device verification page (`/device`) act on
    # behalf of a resource owner, and Authly does not own the login. The host application supplies the
    # signed-in owner here, from its own session. It is the ONLY source of the subject: `user_id` and
    # `consent` request parameters are never read. While it is unset those endpoints refuse every request.
    property authenticate_user : OwnerAuthenticator? = nil
    property render_consent : Proc(HTTP::Server::Context, AuthorizationRequest, String, String, Nil)? = nil
    property userinfo : Proc(String, Hash(String, JSON::Any))? = nil
    # Trusted host callback; never populated from OAuth request parameters.
    property issuance_options : Proc(String, String, IssuanceOptions)? = nil
    property issue_refresh_tokens : Bool = true
    property grant_types : Array(String) = %w[authorization_code client_credentials password refresh_token implicit urn:ietf:params:oauth:grant-type:device_code]
    property signing_key_id : String? = nil
    property verification_keys : Hash(String, String) = {} of String => String

    # Optional. When nobody is signed in, redirect to the URL this returns (a login page that sends the
    # owner back afterwards) instead of answering 401 `login_required`.
    property login_url : LoginRedirect? = nil

    # How long a consent form (and its anti-CSRF token) stays valid.
    property consent_ttl : Time::Span = 10.minutes

    property issuer : String = "The Authority Server Provider"
    property secret_key : String = Random::Secure.hex(16)
    # The key tokens are verified with. For HMAC algorithms (the default) it has to be the
    # signing key, so it follows `secret_key` until it is set to something else, such as the
    # public half of an asymmetric pair.
    setter public_key : String?
    property refresh_ttl : Time::Span = 1.day
    # How long a refresh token family (the chain of tokens one sign-in yields through rotation) may be renewed
    # in all, counted from the sign-in: no refresh token outlives it, however often it is rotated.
    property refresh_absolute_ttl : Time::Span = 30.days
    property code_ttl : Time::Span = 5.minutes
    property access_ttl : Time::Span = 1.hour
    property owners : AuthorizableOwner = Owners.new
    property clients : AuthorizableClient = Clients.new
    property token_store : TokenStore = InMemoryStore.new
    property algorithm : JWT::Algorithm = JWT::Algorithm::HS256
    property token_strategy : Symbol = :jwt
    property state_store : StateStore = InMemoryStateStore.new
    property device_code_store : DeviceCodeStore = InMemoryDeviceCodeStore.new

    # Throttles guessing at the device verification page. Share it between nodes, and make its `increment` atomic
    # (see `AttemptLimiter`).
    property attempt_limiter : AttemptLimiter = InMemoryAttemptLimiter.new

    # Throttles failed authentications at the registration endpoint. A limiter of its own, so that a flood of failed
    # registrations from many sources cannot fill the device limiter (a full limiter refuses every new key).
    property registration_limiter : AttemptLimiter = InMemoryAttemptLimiter.new

    # Who a request counts as for `attempt_limiter` and `registration_limiter`: the client address by default. Behind a reverse proxy that is
    # the proxy, so return the address your proxy vouches for (or nil to count by account only).
    property attempt_source : AttemptSource = ->(context : HTTP::Server::Context) { context.request.remote_address.try(&.as?(Socket::IPAddress).try(&.address)) }

    # User code lookups one signed-in owner, and one source, may make at the device page per window (an approval is two).
    property device_attempt_limit : Int32 = 10
    property device_attempt_window : Time::Span = 15.minutes

    # The `aud` of the access tokens issued, i.e. which API they are for. Defaults to `base_url`.
    # A resource server that sets the same `audience` on its verifier refuses tokens meant for others.
    property access_token_audience : String? = nil

    # Blank counts as unset: with neither an audience nor a `base_url`, tokens carry no `aud`.
    def token_audience : String?
      access_token_audience.presence || base_url.presence
    end

    def public_key : String
      @public_key || secret_key
    end

    # PKCE Enforcement
    property? enforce_pkce : Bool = false
    property? enforce_pkce_s256 : Bool = false

    # OpenID Connect Configuration
    property base_url : String = "http://localhost:8080"

    # Dynamic Client Registration
    property? allow_dynamic_registration : Bool = false
    property registration_access_token : String? = nil
    property authenticate_registration : RegistrationAuthenticator? = nil
    property registration_grant_types : Array(String) = ["authorization_code", "refresh_token"]
    property registration_response_types : Array(String) = ["code"]
    property registration_scopes : Array(String) = [] of String
    property registration_max_body : Int32 = 16 * 1024
    # Failed authentications per source per window; requests with valid credentials are not counted.
    property registration_rate_limit : Int32 = 10
    property registration_rate_window : Time::Span = 1.hour
    property client_store : ClientStore = InMemoryClientStore.new

    # Certificate-Bound Tokens (mTLS)
    property? require_certificate_bound_tokens : Bool = false
    property trusted_ca_certificates : Array(String) = [] of String

    # Pushed Authorization Requests (PAR)
    property par_store : PARStore = InMemoryPARStore.new
    property par_ttl : Time::Span = 90.seconds
    property? require_par : Bool = false

    # JWT Secured Authorization Response Mode (JARM)
    property jarm_signing_key : String? = nil
    property jarm_signing_alg : JWT::Algorithm = JWT::Algorithm::RS256
    property jarm_encryption_key : String? = nil
    property jarm_encryption_alg : String? = nil
    property jarm_encryption_enc : String? = nil
    property default_jarm_response_mode : String? = nil
    property jarm_lifetime : Time::Span = 10.minutes
  end
end
