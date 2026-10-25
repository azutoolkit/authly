require "base64"
require "json"
require "openssl/hmac"
require "crypto/subtle"

module Authly
  # A signed, expiring, purpose-bound token for the forms Authly renders (consent, device approval).
  #
  # The claims travel in the form and cannot be changed by the browser; the HMAC key is derived from
  # `Authly.config.secret_key` and the purpose, so a token for one form is useless for another.
  # Handlers put the authenticated subject in the claims and compare it with the subject of the
  # POST: a token handed to one user cannot be replayed by (or against) another.
  module FormToken
    def self.issue(purpose : String, claims : Hash(String, String), ttl : Time::Span) : String
      payload = claims.merge({"purpose" => purpose, "exp" => ttl.from_now.to_unix.to_s})
      body = Base64.urlsafe_encode(payload.to_json, padding: false)
      "#{body}.#{sign(purpose, body)}"
    end

    # The claims when the token is genuine, unexpired and issued for `purpose`; nil otherwise.
    def self.verify(purpose : String, token : String) : Hash(String, String)?
      body, dot, mac = token.partition('.')
      return if dot.empty? || body.empty?
      return unless Crypto::Subtle.constant_time_compare(sign(purpose, body), mac)

      claims = Hash(String, String).from_json(String.new(Base64.decode(body)))
      return unless claims["purpose"]? == purpose
      return unless (expires = claims["exp"]?.try(&.to_i64?)) && expires > Time.utc.to_unix

      claims
    rescue JSON::ParseException | Base64::Error | ArgumentError
      nil
    end

    private def self.sign(purpose : String, body : String) : String
      key = OpenSSL::HMAC.digest(:sha256, Authly.config.secret_key, "authly-form-token:#{purpose}")
      OpenSSL::HMAC.hexdigest(:sha256, key, body)
    end
  end
end
