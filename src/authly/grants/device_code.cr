module Authly
  class DeviceCode
    include GrantStrategy

    getter client_id : String
    getter device_code : String

    def initialize(@client_id : String, @device_code : String)
    end

    # RFC 8628 section 3.5: seconds added to the interval each time the device polls too fast.
    SLOW_DOWN_STEP = 5

    @user_id : String? = nil

    def authorized? : Bool
      validate!
      true
    end

    # The owner who approved the device, so the token is about them and not about nobody.
    def subject : String?
      @user_id.try { |user_id| owner_subject(user_id) }
    end

    private def validate!
      device_data = Authly.config.device_code_store.fetch(@device_code)

      raise Error.invalid_grant unless device_data
      raise Error.invalid_grant if device_data.expired?
      raise Error.invalid_grant unless device_data.client_id == @client_id

      raise Error.access_denied if device_data.denied?

      enforce_interval!(device_data)
      raise Error.authorization_pending unless device_data.verified?

      redeem!
      @user_id = device_data.user_id
    end

    # A device that polls faster than the interval it was given is told to slow down and its interval grows;
    # the clock restarts at every poll, so hammering never gets through.
    private def enforce_interval!(device_data : DeviceCodeData)
      now = Time.utc
      last = device_data.last_polled_at
      too_fast = !last.nil? && now - last < device_data.interval.seconds
      device_data.interval += SLOW_DOWN_STEP if too_fast
      device_data.last_polled_at = now
      Authly.config.device_code_store.update(@device_code, device_data)
      raise Error.slow_down if too_fast
    end

    # An approval is good for one token, however many requests present the device code at once.
    private def redeem!
      raise Error.invalid_grant unless Authly.config.token_store.consume("device-code:#{@device_code}")
      Authly.config.device_code_store.delete(@device_code)
    end

    # No 0, 1, I or O. Eight of 32 characters are 40 bits, which the attempt limit at the verification page makes unguessable.
    USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    def self.generate_user_code : String
      # Generate a user-friendly code (e.g., "ABCD-EFGH")
      code = Array.new(8) { USER_CODE_ALPHABET[Random::Secure.rand(USER_CODE_ALPHABET.size)] }.join
      "#{code[0..3]}-#{code[4..7]}"
    end

    # What a person typed as "ABCD-EFGH" (any case, dash optional, surrounding blanks), or nil when it
    # cannot be a user code, so nothing malformed ever reaches a store.
    def self.normalize_user_code(input : String?) : String?
      code = input.to_s.strip.upcase.delete('-')
      return unless code.size == 8 && code.each_char.all? { |char| USER_CODE_ALPHABET.includes?(char) }
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
