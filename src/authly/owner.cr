module Authly
  struct Owner
    property username : String
    property password : String

    def initialize(@username, @password)
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

    def id_token(user_id : String) : Hash(String, String | Int64)
      {
        "sub"     => Random::Secure.hex(32),
        "iat"     => Time.utc.to_unix,
        "exp"     => 1.hour.from_now.to_unix,
        "user_id" => user_id,
      }
    end

    def each
      @owners.each { |owner| yield owner }
    end
  end
end
