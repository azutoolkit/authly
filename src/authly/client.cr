require "uuid"

module Authly
  struct Client
    getter name : String
    getter id : String
    getter secret : String
    getter redirect_uri : String
    getter scopes : String
    getter grant_types : String
    getter jarm_signing_alg : String?
    getter jarm_encryption_alg : String?
    getter jarm_encryption_enc : String?
    getter public_key : String?

    def initialize(
      @name,
      @secret,
      @redirect_uri,
      @id,
      @scopes = "read",
      @grant_types = "authorization_code client_credentials password refresh_token",
      @jarm_signing_alg = nil,
      @jarm_encryption_alg = nil,
      @jarm_encryption_enc = nil,
      @public_key = nil,
    )
    end
  end

  class Clients
    include AuthorizableClient
    include Enumerable(Authly::Client)

    def initialize
      @clients = [] of Client
    end

    def <<(client : Client)
      @clients << client
    end

    def valid_redirect?(client_id, redirect_uri) : Bool
      any? do |client|
        client.id == client_id && client.redirect_uri == redirect_uri
      end
    end

    def authorized?(client_id, client_secret)
      any? do |client|
        client.id == client_id && client.secret == client_secret
      end
    end

    def authorized?(client_id, secret, redirect_uri, code, verifier : String? = nil)
      any? do |client|
        client.id == client_id && client.secret == secret && redirect_uri == redirect_uri
      end
    end

    def each(& : Client -> _)
      @clients.each { |client| yield client }
    end

    def allowed_scopes?(client_id, scopes) : Bool
      the_client = self.find { |client| client.id == client_id }
      return false unless the_client

      scopes.split(" ").all? do |scope|
        the_client.scopes.split(" ").includes?(scope)
      end
    rescue
      false
    end

    def allowed_grant_type?(client_id, grant_type) : Bool
      the_client = self.find { |client| client.id == client_id }
      return false unless the_client

      the_client.grant_types.split(" ").includes?(grant_type)
    rescue
      false
    end

    # JARM methods
    def jarm_required?(client_id : String) : Bool
      the_client = self.find { |client| client.id == client_id }
      return false unless the_client

      !the_client.jarm_signing_alg.nil?
    end

    def jarm_signing_algorithm(client_id : String) : String?
      the_client = self.find { |client| client.id == client_id }
      return nil unless the_client

      the_client.jarm_signing_alg
    end

    def jarm_encryption_algorithm(client_id : String) : String?
      the_client = self.find { |client| client.id == client_id }
      return nil unless the_client

      the_client.jarm_encryption_alg
    end

    def jarm_encryption_encoding(client_id : String) : String?
      the_client = self.find { |client| client.id == client_id }
      return nil unless the_client

      the_client.jarm_encryption_enc
    end

    def client_public_key(client_id : String) : String?
      the_client = self.find { |client| client.id == client_id }
      return nil unless the_client

      the_client.public_key
    end
  end
end
