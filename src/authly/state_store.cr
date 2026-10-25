module Authly
  # Single-use values with a lifetime (consent and device form nonces).
  #
  # `consume` is the only check handlers make, so it has to be atomic: of several concurrent callers
  # (also across processes, for a shared store) exactly one gets `true`. Implement it as one
  # delete-and-report operation (Redis `DEL` returning 1, SQL `DELETE ... WHERE` with affected rows),
  # never as `valid?` followed by a delete. With more than one node the store must be shared.
  module StateStore
    abstract def store(state : String, ttl : Time::Span = 5.minutes)

    # Informational only: Authly's handlers never call it (a check followed by `consume` is not atomic).
    abstract def valid?(state : String) : Bool

    # true when `state` was stored, has not expired and has not been consumed before
    abstract def consume(state : String) : Bool
  end

  class InMemoryStateStore
    include StateStore

    # Live nonces kept at most; past it the oldest are dropped, so a signed-in user requesting consent pages
    # in a loop cannot grow the hash without bound (a dropped nonce just means that form must be reloaded).
    MAX_ENTRIES = 10_000

    # Every this many writes, once at least SWEEP_THRESHOLD entries exist, expired entries are removed.
    # The sweep is at most MAX_ENTRIES long, and small stores are never swept.
    SWEEP_EVERY     =  64
    SWEEP_THRESHOLD = 256

    @store : Hash(String, Time)
    @writes = 0
    @mutex = Mutex.new

    def initialize(@default_ttl : Time::Span = 5.minutes)
      @store = Hash(String, Time).new
    end

    def store(state : String, ttl : Time::Span = 5.minutes)
      @mutex.synchronize do
        @writes += 1
        sweep if @writes % SWEEP_EVERY == 0 && @store.size >= SWEEP_THRESHOLD
        @store.shift if @store.size >= MAX_ENTRIES && !@store.has_key?(state)
        @store[state] = ttl.from_now
      end
    end

    def valid?(state : String) : Bool
      @mutex.synchronize do
        expiration = @store[state]?
        !expiration.nil? && Time.utc < expiration
      end
    end

    def consume(state : String) : Bool
      @mutex.synchronize do
        expiration = @store.delete(state)
        !expiration.nil? && Time.utc < expiration
      end
    end

    def size : Int32
      @mutex.synchronize { @store.size }
    end

    # Clean up expired states
    def cleanup_expired
      @mutex.synchronize { sweep }
    end

    private def sweep
      now = Time.utc
      @store.reject! { |_state, expiration| now >= expiration }
    end
  end
end
