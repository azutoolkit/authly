module Authly
  # Interface for storing dynamically registered clients
  module ClientStore
    abstract def store(client : DynamicClient) : Bool
    abstract def fetch(client_id : String) : DynamicClient?
    abstract def delete(client_id : String) : Bool
    abstract def update(client : DynamicClient) : Bool
  end

  # In-memory implementation for development/testing
  class InMemoryClientStore
    include ClientStore

    def initialize
      @clients = {} of String => DynamicClient
    end

    def store(client : DynamicClient) : Bool
      @clients[client.client_id] = client
      true
    end

    def fetch(client_id : String) : DynamicClient?
      @clients[client_id]?
    end

    def delete(client_id : String) : Bool
      @clients.delete(client_id) != nil
    end

    def update(client : DynamicClient) : Bool
      if @clients.has_key?(client.client_id)
        @clients[client.client_id] = client
        true
      else
        false
      end
    end
  end
end
