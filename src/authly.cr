require "jwt"
require "json"
require "./authly/authorizable_owner"
require "./authly/authorizable_client"
require "./authly/token_store"
require "./authly/state_store"
require "./authly/attempt_limiter"
require "./authly/device_code_store"
require "./authly/par_store"
require "./authly/token_generator"
require "./authly/client_store"
require "./authly/dynamic_client"
require "./authly/certificate_validator"
require "./authly/token_binder"
require "./authly/**"
require "log"

module Authly
  CONFIG = Configuration.new

  def self.configure(&)
    yield CONFIG
  end

  def self.config
    CONFIG
  end

  def self.clients
    CONFIG.clients
  end

  def self.owners
    CONFIG.owners
  end

  def self.code(response_type, *args)
    ResponseType.new(response_type, *args).decode
  end

  def self.access_token(grant_type, **args)
    Grant.new(grant_type, **args).token
  end

  def self.jwt_encode(payload, configuration : Configuration = config)
    if kid = configuration.signing_key_id
      JWT.encode(payload, configuration.secret_key, configuration.algorithm, kid: kid)
    else
      JWT.encode(payload, configuration.secret_key, configuration.algorithm)
    end
  end

  def self.jwt_decode(token)
    decode_with(token, config)
  end

  def self.jwt_decode(token, secret_key : String)
    JWT.decode(token, secret_key, config.algorithm, iss: config.issuer)
  end

  def self.decode_with(token : String, configuration : Configuration)
    if configuration.verification_keys.empty?
      JWT.decode(token, configuration.public_key, configuration.algorithm, iss: configuration.issuer)
    else
      JWT.decode(token, algorithm: configuration.algorithm, iss: configuration.issuer) do |header, _payload|
        kid = header["kid"]?.try(&.as_s?)
        (kid && configuration.verification_keys[kid]?) || raise JWT::DecodeError.new("Unknown signing key")
      end
    end
  end

  def self.revoke(token)
    TokenManager.instance.revoke(token)
  end

  def self.revoked?(token)
    TokenManager.instance.revoked?(token)
  end

  def self.valid?(token)
    TokenManager.instance.valid?(token)
  end

  def self.introspect(token : String)
    TokenManager.instance.introspect(token)
  end
end
