require "base64"
require "crypto/subtle"
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
      # RFC 7636 section 4.2: BASE64URL-ENCODE(SHA256(verifier)) without padding. The padded
      # standard base64 this library used to expect is still accepted, so clients written
      # against it keep working.
      def valid?(code_verifier)
        digest = Digest::SHA256.digest(code_verifier)
        {Base64.urlsafe_encode(digest, padding: false), Base64.strict_encode(digest)}.any? do |expected|
          Crypto::Subtle.constant_time_compare(code, expected)
        end
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
