module Authly
  struct Owner
    property id : String = Random::Secure.hex(16)
    property name : String = ""
    property email : String = ""
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
      user = find! { |owner| owner.id == user_id }
      {
        "sub"   => user_id,
        "iat"   => Time.utc.to_unix,
        "exp"   => 1.hour.from_now.to_unix,
        "name"  => user.name,
        "email" => user.email,
      }
    end

    def each(& : Owner -> _)
      @owners.each { |owner| yield owner }
    end
  end
end
