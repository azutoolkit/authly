module Authly
  # Counts events per key inside a window, to throttle guessing (device user codes) and abuse
  # (dynamic client registration). Pluggable like `StateStore`: with more than one node the limiter has to be shared
  # (Redis `INCR` + `EXPIRE`), otherwise every node counts for itself.
  #
  # `exceeded?` and `record` are two calls on purpose: a handler checks before it works and records only what it
  # wants to count (failures), so a success never resets a counter an attacker could top up with a code of their own.
  module AttemptLimiter
    # true when `key` has been recorded `limit` times or more within its window
    abstract def exceeded?(key : String, limit : Int32) : Bool

    # Count one event for `key`. The window starts with the first event and the count is forgotten `window` later.
    abstract def record(key : String, window : Time::Span)
  end

  class InMemoryAttemptLimiter
    include AttemptLimiter

    # Keys kept at most; past it the oldest are dropped, so a flood of distinct keys (spoofed sources, random user
    # codes) cannot grow the hash without bound.
    MAX_ENTRIES = 10_000

    # Every this many writes, once at least SWEEP_THRESHOLD keys exist, expired ones are removed.
    SWEEP_EVERY     =  64
    SWEEP_THRESHOLD = 256

    private record Count, hits : Int32, until : Time

    @counts = Hash(String, Count).new
    @writes = 0
    @mutex = Mutex.new

    def exceeded?(key : String, limit : Int32) : Bool
      @mutex.synchronize do
        count = @counts[key]?
        !count.nil? && Time.utc < count.until && count.hits >= limit
      end
    end

    def record(key : String, window : Time::Span)
      @mutex.synchronize do
        @writes += 1
        sweep if @writes % SWEEP_EVERY == 0 && @counts.size >= SWEEP_THRESHOLD
        @counts.shift if @counts.size >= MAX_ENTRIES && !@counts.has_key?(key)
        @counts[key] = next_count(@counts[key]?, window)
      end
    end

    def size : Int32
      @mutex.synchronize { @counts.size }
    end

    private def next_count(count : Count?, window : Time::Span) : Count
      return Count.new(1, window.from_now) if count.nil? || Time.utc >= count.until
      Count.new(count.hits + 1, count.until)
    end

    private def sweep
      now = Time.utc
      @counts.reject! { |_key, count| now >= count.until }
    end
  end
end
