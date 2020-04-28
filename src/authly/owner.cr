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

    def authorized?(username : String, password : String)
      any? do |owner|
        owner.username == username && owner.password == password
      end
    end

    def each
      @owners.each { |owner| yield owner }
    end
  end
end
