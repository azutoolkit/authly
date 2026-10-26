# Counts through `increment` only: a handler that reads the counter and then `record`s it is not atomic.
class IncrementOnlyLimiter
  include Authly::AttemptLimiter

  getter incremented = [] of String

  def exceeded?(key : String, limit : Int32) : Bool
    @incremented.count(key) >= limit
  end

  def record(key : String, window : Time::Span)
    raise "check-then-record is not atomic: use increment"
  end

  def increment(key : String, window : Time::Span) : Int32
    @incremented << key
    @incremented.count(key).to_i32
  end
end
