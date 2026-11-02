module Authly
  struct Owner
    property id : String = Random::Secure.hex(16)
    property username : String
    property password : String
    property email : String? = nil
    property public_key : String? = nil
    property secret_key : String? = nil
    property key_id : String? = nil
    property social_identities : Hash(String, String) = {} of String => String

    def initialize(
      @username : String,
      @password : String,
      @public_key : String? = nil,
      @secret_key : String? = nil,
      @key_id : String? = nil,
      @id : String = Random::Secure.hex(16),
      @email : String? = nil,
      @social_identities : Hash(String, String) = {} of String => String,
    )
    end
  end

  class Owners
    include AuthorizableOwner
    include Enumerable(Authly::Owner)

    def initialize
      @owners = [] of Owner
    end

    def <<(owner : Owner)
      @owners << owner
    end

    def authorized?(username : String, password : String) : Bool
      any? do |owner|
        owner.username == username && owner.password == password
      end
    end

    def verify_challenge_response?(
      challenge : String,
      response : String,
      identifier : String? = nil,
      username : String? = nil,
      owner_id : String? = nil,
      key_id : String? = nil,
      algorithm : String? = nil,
    ) : Bool
      target = identifier.presence || owner_id.presence || username.presence || key_id.presence
      if target
        owner = find_owner(target)
        return false unless owner

        ChallengeVerifier.verify?(
          challenge: challenge,
          response: response,
          public_key: owner.public_key,
          secret: owner.secret_key.presence || owner.password,
          algorithm: algorithm,
        )
      else
        any? do |candidate|
          ChallengeVerifier.verify?(
            challenge: challenge,
            response: response,
            public_key: candidate.public_key,
            secret: candidate.secret_key.presence || candidate.password,
            algorithm: algorithm,
          )
        end
      end
    end

    def find_owner(identifier : String) : Owner?
      find do |owner|
        owner.username == identifier || owner.id == identifier || owner.key_id == identifier || owner.email == identifier
      end
    end

    def resolve_social_owner(profile : SocialProfile) : String?
      matched = find do |owner|
        owner.social_identities[profile.provider]? == profile.uid ||
          (profile.email_verified? && !profile.email.to_s.empty? &&
            (owner.email == profile.email || owner.username == profile.email))
      end
      matched.try(&.id)
    end

    def id_token(user_id : String) : Hash(String, String | Int64)
      user = find! { |owner| owner.username == user_id || owner.id == user_id || owner.key_id == user_id || owner.email == user_id }
      claims = {
        "user_id" => user.username,
        "sub"     => user.id,
        "iat"     => Time.utc.to_unix,
        "exp"     => Authly.config.access_ttl.from_now.to_unix,
        "iss"     => Authly.config.issuer,
      }
      if email = user.email.presence
        claims["email"] = email
      end
      claims
    end

    def each(& : Owner -> _)
      @owners.each { |owner| yield owner }
    end
  end
end
