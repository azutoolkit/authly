require "base64"
require "openssl"

module Authly
  # The JSON Web Key Set (RFC 7517) for the key tokens are verified with.
  #
  # Only asymmetric algorithms have something to publish: with RS* or ES* the set holds the
  # public key in `config.public_key` (a PEM). With HMAC (the default) the verification key is the
  # signing secret, which must never be published, so the set is empty.
  class JWKS
    ALGORITHMS = %w[RS256 RS384 RS512 ES256 ES384 ES512]

    def initialize(@config : Configuration = Authly.config)
    end

    def keys : Array(Hash(String, String))
      name = algorithm_name
      return [] of Hash(String, String) unless name

      [PublicKey.parse(@config.public_key).to_jwk(name)]
    end

    def to_json(json : JSON::Builder) : Nil
      {keys: keys}.to_json(json)
    end

    private def algorithm_name : String?
      name = @config.algorithm.to_s
      name if ALGORITHMS.includes?(name)
    end

    # A public key read from a PEM `PUBLIC KEY` (SubjectPublicKeyInfo) or `RSA PUBLIC KEY` (PKCS#1).
    # Private keys are refused outright.
    struct PublicKey
      RSA_OID = Bytes[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
      EC_OID  = Bytes[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]
      CURVES  = {
        Bytes[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => {"P-256", 32},
        Bytes[0x2b, 0x81, 0x04, 0x00, 0x22]                   => {"P-384", 48},
        Bytes[0x2b, 0x81, 0x04, 0x00, 0x23]                   => {"P-521", 66},
      }
      PEM_BLOCK = /-----BEGIN ([A-Z ]+)-----(.+?)-----END \1-----/m

      def self.parse(pem : String) : PublicKey
        label, body = PEM_BLOCK.match(pem).try { |match| {match[1], match[2]} } || raise ArgumentError.new("public_key is not a PEM")
        raise ArgumentError.new("public_key must be a public key") unless label.ends_with?("PUBLIC KEY")

        der = Base64.decode(body)
        label == "RSA PUBLIC KEY" ? rsa(DER.new(der).enter(0x30)) : spki(DER.new(der).enter(0x30))
      rescue IndexError | Base64::Error
        raise ArgumentError.new("public_key is not a valid PEM public key")
      end

      private def self.spki(sequence : DER) : PublicKey
        algorithm = sequence.enter(0x30)
        oid = algorithm.read(0x06)
        bits = sequence.read(0x03)[1..]

        if oid == RSA_OID
          rsa(DER.new(bits).enter(0x30))
        elsif oid == EC_OID
          ec(CURVES[algorithm.read(0x06)]? || raise(ArgumentError.new("Unsupported curve")), bits)
        else
          raise ArgumentError.new("Unsupported public key type")
        end
      end

      private def self.rsa(key : DER) : PublicKey
        new({"kty" => "RSA", "n" => b64(unsigned(key.read(0x02))), "e" => b64(unsigned(key.read(0x02)))})
      end

      private def self.ec(curve : {String, Int32}, point : Bytes) : PublicKey
        name, size = curve
        raise ArgumentError.new("Unsupported point format") unless point.size == 1 + 2 * size && point[0] == 0x04

        new({"kty" => "EC", "crv" => name, "x" => b64(point[1, size]), "y" => b64(point[1 + size, size])})
      end

      private def self.unsigned(integer : Bytes) : Bytes
        integer.size > 1 && integer[0] == 0 ? integer[1..] : integer
      end

      private def self.b64(bytes : Bytes) : String
        Base64.urlsafe_encode(bytes, padding: false)
      end

      def initialize(@members : Hash(String, String))
      end

      # `kid` is the RFC 7638 thumbprint, so it follows the key.
      def to_jwk(algorithm : String) : Hash(String, String)
        @members.merge({"use" => "sig", "alg" => algorithm, "kid" => thumbprint})
      end

      private def thumbprint : String
        required = @members["kty"] == "RSA" ? {"e", "kty", "n"} : {"crv", "kty", "x", "y"}
        canonical = required.map { |name| "#{name.to_json}:#{@members[name].to_json}" }.join(',')
        Base64.urlsafe_encode(OpenSSL::Digest.new("SHA256").update("{#{canonical}}").final, padding: false)
      end
    end

    # Just enough DER to walk a public key: definite lengths, one TLV at a time.
    private struct DER
      def initialize(@bytes : Bytes)
        @position = 0
      end

      def read(tag : UInt8) : Bytes
        raise ArgumentError.new("Unexpected DER tag") unless @bytes[@position] == tag

        length = @bytes[@position + 1].to_i
        header = 2
        if length >= 0x80
          header += length & 0x7f
          raise ArgumentError.new("Unsupported DER length") unless (1..3).includes?(length & 0x7f)
          length = @bytes[@position + 2, length & 0x7f].reduce(0) { |sum, byte| (sum << 8) | byte }
        end

        content = @bytes[@position + header, length]
        @position += header + length
        content
      end

      def enter(tag : UInt8) : DER
        DER.new(read(tag))
      end
    end
  end
end
