module Authly
  struct Challenge
    include JSON::Serializable

    property challenge_id : String
    property challenge : String
    property client_id : String
    property username : String?
    property owner_id : String?
    property key_id : String?
    property expires_at : Time
    property? consumed : Bool = false
    property attempts : Int32 = 0

    def initialize(
      @challenge_id : String,
      @challenge : String,
      @client_id : String,
      @expires_at : Time,
      @username : String? = nil,
      @owner_id : String? = nil,
      @key_id : String? = nil,
      @consumed : Bool = false,
      @attempts : Int32 = 0,
    )
    end

    def self.generate(
      client_id : String,
      ttl : Time::Span = Authly.config.challenge_ttl,
      username : String? = nil,
      owner_id : String? = nil,
      key_id : String? = nil,
    ) : Challenge
      new(
        challenge_id: Random::Secure.hex(16),
        challenge: Random::Secure.hex(32),
        client_id: client_id,
        expires_at: Time.utc + ttl,
        username: username,
        owner_id: owner_id,
        key_id: key_id,
      )
    end

    def expired? : Bool
      Time.utc >= @expires_at
    end

    def expires_in : Int32
      remaining = (@expires_at - Time.utc).total_seconds.round.to_i
      remaining > 0 ? remaining : 0
    end

    def identifier : String?
      @owner_id.presence || @username.presence || @key_id.presence
    end
  end

  module ChallengeStore
    abstract def store(challenge : Challenge) : Challenge
    abstract def fetch(challenge_id : String) : Challenge?

    # Atomically deletes and returns an unexpired challenge, or nil if unknown, expired, or already consumed.
    abstract def consume!(challenge_id : String) : Challenge?

    abstract def delete(challenge_id : String) : Bool
    abstract def cleanup_expired : Nil

    def store(challenge_id : String, challenge : Challenge) : Challenge
      store(challenge)
    end

    def valid?(challenge_id : String) : Bool
      !fetch(challenge_id).nil?
    end

    # Atomically records a verification attempt against `challenge_id`.
    # Raises `Error.expired_challenge` if expired, or `Error.invalid_grant` if missing/consumed.
    def record_attempt!(challenge_id : String, max_attempts : Int32 = 1) : Challenge
      consume!(challenge_id) || raise Error.invalid_grant
    end
  end

  class InMemoryChallengeStore
    include ChallengeStore

    MAX_ENTRIES     = 50_000
    SWEEP_EVERY     =     64
    SWEEP_THRESHOLD =    256

    @store : Hash(String, Challenge)
    @expired_ids : Set(String)
    @writes = 0
    @mutex = Mutex.new

    def initialize
      @store = Hash(String, Challenge).new
      @expired_ids = Set(String).new
    end

    def store(challenge : Challenge) : Challenge
      @mutex.synchronize do
        @writes += 1
        sweep if @writes % SWEEP_EVERY == 0 && @store.size >= SWEEP_THRESHOLD
        evict_oldest if @store.size >= MAX_ENTRIES && !@store.has_key?(challenge.challenge_id)
        @expired_ids.delete(challenge.challenge_id)
        @store[challenge.challenge_id] = challenge
      end
    end

    def fetch(challenge_id : String) : Challenge?
      @mutex.synchronize do
        data = @store[challenge_id]?
        return if data.nil? || data.expired? || data.consumed?
        data
      end
    end

    def consume!(challenge_id : String) : Challenge?
      @mutex.synchronize do
        data = @store.delete(challenge_id)
        return unless data
        if data.expired?
          track_expired(challenge_id)
          return
        end
        return if data.consumed?

        data.consumed = true
        data.attempts += 1
        data
      end
    end

    def record_attempt!(challenge_id : String, max_attempts : Int32 = 1) : Challenge
      @mutex.synchronize do
        data = @store[challenge_id]?
        if data
          if data.expired?
            @store.delete(challenge_id)
            track_expired(challenge_id)
            raise Error.expired_challenge
          end
          if data.consumed?
            @store.delete(challenge_id)
            raise Error.invalid_grant
          end

          data.attempts += 1
          if max_attempts <= 1 || data.attempts >= max_attempts
            data.consumed = true
            @store.delete(challenge_id)
          else
            @store[challenge_id] = data
          end
          return data
        end

        raise Error.expired_challenge if @expired_ids.includes?(challenge_id)
        raise Error.invalid_grant
      end
    end

    def delete(challenge_id : String) : Bool
      @mutex.synchronize do
        @expired_ids.delete(challenge_id)
        !@store.delete(challenge_id).nil?
      end
    end

    def size : Int32
      @mutex.synchronize { @store.size }
    end

    def cleanup_expired : Nil
      @mutex.synchronize { sweep }
    end

    private def sweep : Nil
      @store.each do |id, data|
        if data.expired?
          @store.delete(id)
          track_expired(id)
        end
      end
    end

    private def track_expired(challenge_id : String) : Nil
      @expired_ids.clear if @expired_ids.size >= MAX_ENTRIES
      @expired_ids.add(challenge_id)
    end

    private def evict_oldest : Nil
      if oldest = @store.first_key?
        @store.delete(oldest)
      end
    end
  end
end
