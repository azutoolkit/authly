module Authly::Stores
  module Conformance
    extend Spec::Methods

    # Runs *count* calls of the block at once, one fiber each, and collects their answers.
    def self.concurrently(count : Int32, &block : -> T) : Array(T) forall T
      results = Channel(T | Exception).new(count)
      count.times { spawn { results.send(attempt(&block)) } }
      Array(T).new(count) do
        result = results.receive
        raise result if result.is_a?(Exception)
        result
      end
    end

    private def self.attempt(&block : -> T) : T | Exception forall T
      block.call
    rescue e
      e
    end

    def self.random_id : String
      Random::Secure.hex(16)
    end
  end
end
