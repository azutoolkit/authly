module Authly
  # An `AttemptLimiter` in Redis, shared by every node: `increment` is one script (`INCR`, and `PEXPIRE` when the key
  # has no TTL yet), so a burst of parallel requests is counted exactly and every counter expires with its window.
  class RedisAttemptLimiter
    include AttemptLimiter

    INCREMENT = <<-LUA
      local count = redis.call('INCR', KEYS[1])
      if redis.call('PTTL', KEYS[1]) < 0 then
        redis.call('PEXPIRE', KEYS[1], ARGV[1])
      end
      return count
      LUA

    def initialize(@redis : RedisConnection)
    end

    def exceeded?(key : String, limit : Int32) : Bool
      count = @redis.run(&.get(@redis.key("attempts", key)))
      !count.nil? && count.to_i64 >= limit
    end

    def increment(key : String, window : Time::Span) : Int32
      args = [RedisConnection.milliseconds(window)]
      count = @redis.run(&.eval(INCREMENT, [@redis.key("attempts", key)], args)).as(Int64)
      {count, Int32::MAX.to_i64}.min.to_i32
    end
  end
end
