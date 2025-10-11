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

    def initialize(
      @device_code,
      @user_code,
      @client_id,
      @scope,
      @expires_at,
      @interval = 5,
      @verified = false,
      @user_id = nil,
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

    @store : Hash(String, DeviceCodeData)
    @user_code_index : Hash(String, String) # Maps user_code to device_code

    def initialize
      @store = Hash(String, DeviceCodeData).new
      @user_code_index = Hash(String, String).new
    end

    def store(device_code : String, data : DeviceCodeData)
      @store[device_code] = data
      @user_code_index[data.user_code] = device_code
    end

    def fetch(device_code : String) : DeviceCodeData?
      data = @store[device_code]?
      return nil if data.nil? || data.expired?
      data
    end

    def fetch_by_user_code(user_code : String) : DeviceCodeData?
      device_code = @user_code_index[user_code]?
      return nil unless device_code
      fetch(device_code)
    end

    def update(device_code : String, data : DeviceCodeData)
      @store[device_code] = data
    end

    def delete(device_code : String)
      data = @store.delete(device_code)
      @user_code_index.delete(data.user_code) if data
    end

    # Clean up expired device codes
    def cleanup_expired
      @store.reject! do |_, data|
        if data.expired?
          @user_code_index.delete(data.user_code)
          true
        else
          false
        end
      end
    end
  end
end
