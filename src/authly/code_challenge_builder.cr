require "digest/sha256"

module Authly
  alias CodeChallenge = CodeChallengeBuilder::Plain | CodeChallengeBuilder::S256

  module CodeChallengeBuilder
    record Plain, code : String do
      def valid?(code_verifier)
        code == code_verifier
      end
    end

    record S256, code : String do
      def valid?(code_verifier)
        code == Digest::SHA256.base64digest(code_verifier)
      end
    end

    def self.build(challenge : String = "", method : String = "S256")
      case method
      when "plain"
        Plain.new(challenge)
      when "S256"
        S256.new(challenge)
      else
        raise ArgumentError.new("Unsupported code challenge method: #{method}. Only 'plain' and 'S256' are supported.")
      end
    end
  end
end
