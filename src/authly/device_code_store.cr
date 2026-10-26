module Authly
  struct DeviceCodeData
    include JSON::Serializable

    property device_code : String
    property user_code : String
    property client_id : String
    property scope : String
    property expires_at : Time
    property interval : Int32
    property? verified : Bool = false
    property user_id : String?
    # When the device last asked for a token; polling faster than `interval` is answered `slow_down`.
    property last_polled_at : Time?

    def initialize(
      @device_code,
      @user_code,
      @client_id,
      @scope,
      @expires_at,
      @interval = 5,
      @verified = false,
      @user_id = nil,
      @last_polled_at = nil,
    )
    end

    def expired? : Bool
      Time.utc > @expires_at
    end
  end

  module DeviceCodeStore
    abstract def store(device_code : String, data : DeviceCodeData)
    abstract def fetch(device_code : String) : DeviceCodeData?
    abstract def fetch_by_user_code(user_code : String) : DeviceCodeData?
    abstract def update(device_code : String, data : DeviceCodeData)
    abstract def delete(device_code : String)
  end

  class InMemoryDeviceCodeStore
    include DeviceCodeStore

    # Live device authorizations kept at most. `/oauth/device/code` needs no sign-in, so past it the oldest are dropped
    # rather than letting a flood of requests grow the store without bound.
    MAX_ENTRIES = 50_000

    # Every this many writes, once at least SWEEP_THRESHOLD entries exist, expired ones are removed.
    SWEEP_EVERY     =  64
    SWEEP_THRESHOLD = 256

    @store : Hash(String, DeviceCodeData)
    @user_code_index : Hash(String, String) # Maps user_code to device_code
    @writes = 0
    @mutex = Mutex.new

    def initialize
      @store = Hash(String, DeviceCodeData).new
      @user_code_index = Hash(String, String).new
    end

    def store(device_code : String, data : DeviceCodeData)
      @mutex.synchronize do
        @writes += 1
        sweep if @writes % SWEEP_EVERY == 0 && @store.size >= SWEEP_THRESHOLD
        evict_oldest if @store.size >= MAX_ENTRIES && !@store.has_key?(device_code)
        @store[device_code] = data
        @user_code_index[data.user_code] = device_code
      end
    end

    def fetch(device_code : String) : DeviceCodeData?
      @mutex.synchronize { fetch_unlocked(device_code) }
    end

    def fetch_by_user_code(user_code : String) : DeviceCodeData?
      @mutex.synchronize do
        device_code = @user_code_index[user_code]?
        fetch_unlocked(device_code) if device_code
      end
    end

    def update(device_code : String, data : DeviceCodeData)
      @mutex.synchronize { @store[device_code] = data }
    end

    def delete(device_code : String)
      @mutex.synchronize { remove(device_code) }
    end

    def size : Int32
      @mutex.synchronize { @store.size }
    end

    # Clean up expired device codes
    def cleanup_expired
      @mutex.synchronize { sweep }
    end

    private def fetch_unlocked(device_code : String) : DeviceCodeData?
      data = @store[device_code]?
      return if data.nil? || data.expired?
      data
    end

    private def remove(device_code : String)
      data = @store.delete(device_code)
      @user_code_index.delete(data.user_code) if data
    end

    private def sweep
      @store.select { |_, data| data.expired? }.each_key { |device_code| remove(device_code) }
    end

    private def evict_oldest
      oldest = @store.first_key?
      remove(oldest) if oldest
    end
  end
end
