module Authly
  alias CodeChallenge = CodeChallengeBuilder::Plain | CodeChallengeBuilder::S256 | CodeChallengeBuilder::Empty

  module CodeChallengeBuilder
    record Plain, code : String do
      def valid?(code_verifier)
        @code == code_verifier
      end
    end

    record S256, code : String do
      def valid?(code_verifier)
        code == Digest::SHA256.base64digest(code_verifier)
      end
    end

    record Empty, code : String do
      def valid?(code_verifier)
        true
      end
    end

    def self.build(code : String = "", method : String = "")
      case method
      when "plain" then Plain.new(code)
      when "S256"  then S256.new(code)
      else              Empty.new(code)
      end
    end
  end
end
