module Authly
  # A `DeviceCodeStore` in Redis. An authorization lives until its `expires_at`, under the hash of its device code;
  # the user code index holds the hash of the device code key, never the code itself. `update` writes only a code
  # that still exists (`SET XX`): a poll that races a redemption cannot bring a deleted code back.
  class RedisDeviceCodeStore
    include DeviceCodeStore

    # `DeviceCodeData` serializes times in whole seconds; its times are kept here to the millisecond, since `slow_down`
    # compares `last_polled_at` with the poll interval.
    private struct Record
      include JSON::Serializable

      getter data : DeviceCodeData
      getter expires_at_ms : Int64
      getter last_polled_at_ms : Int64?

      def initialize(@data : DeviceCodeData)
        @expires_at_ms = data.expires_at.to_unix_ms
        @last_polled_at_ms = data.last_polled_at.try(&.to_unix_ms)
      end

      def restore : DeviceCodeData
        restored = @data
        restored.expires_at = Time.unix_ms(@expires_at_ms)
        restored.last_polled_at = @last_polled_at_ms.try { |millis| Time.unix_ms(millis) }
        restored
      end
    end

    # Writes the authorization and its user code index together, with the same TTL.
    STORE = <<-LUA
      redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
      redis.call('SET', KEYS[2], KEYS[1], 'PX', ARGV[2])
      return 1
      LUA

    def initialize(@redis : RedisConnection)
    end

    def store(device_code : String, data : DeviceCodeData)
      return unless ttl = ttl(data)
      keys = [device_key(device_code), user_key(data.user_code)]
      @redis.run(&.eval(STORE, keys, [Record.new(data).to_json, ttl]))
    end

    def fetch(device_code : String) : DeviceCodeData?
      read(device_key(device_code))
    end

    def fetch_by_user_code(user_code : String) : DeviceCodeData?
      key = @redis.run(&.get(user_key(user_code)))
      read(key) if key
    end

    def update(device_code : String, data : DeviceCodeData)
      return delete(device_code) unless ttl = ttl(data)
      @redis.run(&.set(device_key(device_code), Record.new(data).to_json, px: ttl, xx: true))
    end

    def delete(device_code : String)
      key = device_key(device_code)
      data = read(key)
      keys = data ? [key, user_key(data.user_code)] : [key]
      @redis.run(&.del(keys))
    end

    private def read(key : String) : DeviceCodeData?
      raw = @redis.run(&.get(key))
      data = Record.from_json(raw).restore if raw
      data unless data.nil? || data.expired?
    end

    private def ttl(data : DeviceCodeData) : Int64?
      left = data.expires_at - Time.utc
      RedisConnection.milliseconds(left) if left.positive?
    end

    private def device_key(device_code : String) : String
      @redis.key("device", device_code)
    end

    private def user_key(user_code : String) : String
      @redis.key("user_code", user_code)
    end
  end
end
