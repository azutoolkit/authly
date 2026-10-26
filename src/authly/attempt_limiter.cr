module Authly
  # Counts events per key inside a window, to throttle guessing (device user codes) and abuse
  # (dynamic client registration). Pluggable like `StateStore`: with more than one node the limiter has to be shared,
  # otherwise every node counts for itself.
  #
  # The handlers count with `increment`, which counts and reads in ONE step: asking `exceeded?` and then `record`ing
  # lets a burst of parallel requests all pass the check before any of them is counted. A shared limiter must make
  # `increment` atomic (Redis: `INCR key`, then `EXPIRE key window` when the answer is 1; or one Lua script) and
  # `exceeded?` a plain read of the same counter. `record` is `increment` without the answer.
  module AttemptLimiter
    # true when `key` has been counted `limit` times or more within its window
    abstract def exceeded?(key : String, limit : Int32) : Bool

    # Count one event for `key` and answer how many events the key has now within its window. The window starts with
    # the first event and the count is forgotten `window` later. A limiter that cannot count (it is full of live keys)
    # answers a count no limit reaches, so the caller refuses: it fails closed.
    abstract def increment(key : String, window : Time::Span) : Int32

    # Count one event for `key`.
    def record(key : String, window : Time::Span)
      increment(key, window)
    end
  end

  class InMemoryAttemptLimiter
    include AttemptLimiter

    # Keys kept at most. A flood of distinct keys (spoofed sources, random user codes) cannot grow the hash without
    # bound: when it is full, expired keys are swept first; if every key is still live, a NEW key is not counted and
    # `increment` answers `FULL`, so callers refuse (fail closed). A live counter is never dropped to make room: that
    # would let an attacker reset their own count by flooding the limiter with other keys.
    MAX_ENTRIES = 10_000

    # What `increment` answers for a new key while the limiter is full of live keys.
    FULL = Int32::MAX

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

    def increment(key : String, window : Time::Span) : Int32
      @mutex.synchronize do
        @writes += 1
        sweep if @writes % SWEEP_EVERY == 0 && @counts.size >= SWEEP_THRESHOLD
        next FULL unless room_for?(key)

        count = next_count(@counts[key]?, window)
        @counts[key] = count
        count.hits
      end
    end

    def size : Int32
      @mutex.synchronize { @counts.size }
    end

    private def room_for?(key : String) : Bool
      return true if @counts.size < MAX_ENTRIES || @counts.has_key?(key)

      sweep
      @counts.size < MAX_ENTRIES
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
