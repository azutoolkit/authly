module Authly
  class DeviceCode
    include GrantStrategy

    getter client_id : String
    getter device_code : String

    def initialize(@client_id : String, @device_code : String)
    end

    def authorized? : Bool
      validate!
      true
    end

    private def validate!
      # Fetch device code data from store
      device_data = Authly.config.device_code_store.fetch(@device_code)

      raise Error.invalid_grant unless device_data
      raise Error.invalid_grant if device_data.expired?
      raise Error.authorization_pending unless device_data.verified

      # Verify client_id matches
      unless device_data.client_id == @client_id
        raise Error.invalid_grant
      end
    end

    def self.generate_user_code : String
      # Generate a user-friendly code (e.g., "ABCD-EFGH")
      chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" # Avoid ambiguous characters
      code = 8.times.map { chars[Random.rand(chars.size)] }.join
      "#{code[0..3]}-#{code[4..7]}"
    end

    def self.create_device_authorization(client_id : String, scope : String) : DeviceCodeData
      device_code = Random::Secure.hex(32)
      user_code = generate_user_code
      expires_at = 15.minutes.from_now

      device_data = DeviceCodeData.new(
        device_code: device_code,
        user_code: user_code,
        client_id: client_id,
        scope: scope,
        expires_at: expires_at,
        interval: 5
      )

      Authly.config.device_code_store.store(device_code, device_data)
      device_data
    end
  end
end
