require "uuid"

module Authly
  class Client
    getter name : String
    getter id : String
    getter secret : String
    getter redirect_uri : String
    getter scopes : String

    def initialize(@name, @secret, @redirect_uri, @id, @scopes = "read")
    end
  end

  class Clients
    include Enumerable(Authly::Client)

    def initialize
      @clients = [] of Client
    end

    def <<(client : Client)
      @clients << client
    end

    def validate_redirect(id, redirect_uri)
      any? do |client|
        client.id == id && client.redirect_uri == redirect_uri
      end
    end

    def validate(id, secret)
      any? do |client|
        client.id == id && client.secret == secret
      end
    end

    def validate(id, secret, redirect_uri)
      any? do |client|
        client.id == id && client.secret == secret && redirect_uri == redirect_uri
      end
    end

    def each
      @clients.each { |client| yield client }
    end
  end
end
