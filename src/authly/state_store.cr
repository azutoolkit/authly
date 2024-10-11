module Authly
  module StateStore
    abstract def store(state : String)
    abstract def valid?(state : String) : Bool
  end

  class InMemoryStateStore
    include StateStore

    @store : Hash(String, Bool)

    def initialize
      @store = Hash(String, Bool).new
    end

    def store(state : String)
      @store[state] = true
    end

    def valid?(state : String) : Bool
      @store.fetch(state, false) == true
    end
  end
end
