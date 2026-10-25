module Authly
  # Single-use values with a lifetime (consent and device form nonces).
  #
  # `consume` is the only check handlers make, so it has to be atomic: of several concurrent callers
  # (also across processes, for a shared store) exactly one gets `true`. Implement it as one
  # delete-and-report operation (Redis `DEL` returning 1, SQL `DELETE ... WHERE` with affected rows),
  # never as `valid?` followed by a delete. With more than one node the store must be shared.
  module StateStore
    abstract def store(state : String, ttl : Time::Span = 5.minutes)
    abstract def valid?(state : String) : Bool

    # true when `state` was stored, has not expired and has not been consumed before
    abstract def consume(state : String) : Bool
  end

  class InMemoryStateStore
    include StateStore

    # Expired entries are swept once per this many writes, so the hash stays bounded without a timer.
    SWEEP_EVERY = 64

    @store : Hash(String, Time)
    @writes = 0
    @mutex = Mutex.new

    def initialize(@default_ttl : Time::Span = 5.minutes)
      @store = Hash(String, Time).new
    end

    def store(state : String, ttl : Time::Span = 5.minutes)
      @mutex.synchronize do
        @store[state] = ttl.from_now
        @writes += 1
        sweep if @writes % SWEEP_EVERY == 0
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
