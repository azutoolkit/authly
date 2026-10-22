module Authly
  # PAR (Pushed Authorization Request) data structure
  struct PARData
    getter params : Hash(String, String)
    getter client_id : String
    getter expires_at : Time

    def initialize(@params : Hash(String, String), @client_id : String, @expires_at : Time)
    end

    def expired? : Bool
      Time.utc >= @expires_at
    end
  end

  # Abstract module for PAR storage
  module PARStore
    abstract def store(request_uri : String, params : Hash(String, String), client_id : String, ttl : Time::Span = 90.seconds)
    abstract def fetch(request_uri : String) : PARData?
    abstract def consume(request_uri : String)
    abstract def valid?(request_uri : String) : Bool
  end

  # In-memory implementation of PAR store
  class InMemoryPARStore
    include PARStore

    @store : Hash(String, PARData)
    @default_ttl : Time::Span

    def initialize(@default_ttl : Time::Span = 90.seconds)
      @store = Hash(String, PARData).new
    end

    def store(request_uri : String, params : Hash(String, String), client_id : String, ttl : Time::Span = 90.seconds)
      expires_at = Time.utc + ttl
      @store[request_uri] = PARData.new(params, client_id, expires_at)
    end

    def fetch(request_uri : String) : PARData?
      par_data = @store[request_uri]?
      return unless par_data
      return if par_data.expired?
      par_data
    rescue
      nil
    end

    def consume(request_uri : String)
      @store.delete(request_uri)
    end

    def valid?(request_uri : String) : Bool
      par_data = @store[request_uri]?
      return false unless par_data
      !par_data.expired?
    rescue
      false
    end

    # Clean up expired request URIs
    def cleanup_expired
      @store.reject! { |_uri, data| data.expired? }
    end
  end
end
