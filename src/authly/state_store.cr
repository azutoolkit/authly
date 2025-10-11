module Authly
  module StateStore
    abstract def store(state : String, ttl : Time::Span = 5.minutes)
    abstract def valid?(state : String) : Bool
    abstract def consume(state : String)
  end

  class InMemoryStateStore
    include StateStore

    @store : Hash(String, Time)

    def initialize(@default_ttl : Time::Span = 5.minutes)
      @store = Hash(String, Time).new
    end

    def store(state : String, ttl : Time::Span = 5.minutes)
      @store[state] = ttl.from_now
    end

    def valid?(state : String) : Bool
      expiration = @store[state]?
      return false unless expiration
      Time.utc < expiration
    rescue
      false
    end

    def consume(state : String)
      @store.delete(state)
    end

    # Clean up expired states
    def cleanup_expired
      now = Time.utc
      @store.reject! { |_state, expiration| now >= expiration }
    end
  end
end
