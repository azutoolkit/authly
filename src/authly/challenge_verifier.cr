require "base64"
require "crypto/subtle"
require "ed25519"
require "openssl"
require "openssl/hmac"
require "openssl_ext"

module Authly
  module ChallengeVerifier
    extend self

    ED25519_SPKI_PREFIX = Bytes[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]

    # Verifies a challenge response using asymmetric signature verification when `public_key` is provided,
    # or HMAC-SHA256 when `secret` is provided.
    def verify?(
      challenge : String,
      response : String,
      public_key : String? = nil,
      secret : String? = nil,
      algorithm : String? = nil,
    ) : Bool
      return false if challenge.empty? || response.empty?

      alg = algorithm.try(&.downcase.strip)
      if alg && (alg.starts_with?("hmac") || alg.starts_with?("hs"))
        return false unless secret
        return verify_hmac?(challenge, response, secret, hmac_digest_symbol(alg))
      end

      if key = public_key.presence
        return true if verify_asymmetric?(challenge, response, key, alg)
        return false unless alg.nil? && secret.presence
      end

      if sec = secret.presence
        return verify_hmac?(challenge, response, sec)
      end

      false
    end

    # Verifies an HMAC challenge response using constant-time comparison across hex and Base64 encodings.
    def verify_hmac?(
      challenge : String,
      response : String,
      secret : String,
      digest_algorithm : OpenSSL::Algorithm = OpenSSL::Algorithm::SHA256,
    ) : Bool
      return false if challenge.empty? || response.empty? || secret.empty?

      expected_bytes = OpenSSL::HMAC.digest(digest_algorithm, secret, challenge)
      expected_hex = expected_bytes.hexstring
      expected_b64 = Base64.strict_encode(expected_bytes)
      expected_b64url = Base64.urlsafe_encode(expected_bytes, padding: false)
      expected_b64url_pad = Base64.urlsafe_encode(expected_bytes, padding: true)

      normalized = response.strip
      match_hex = Crypto::Subtle.constant_time_compare(normalized.downcase, expected_hex)
      match_b64 = Crypto::Subtle.constant_time_compare(normalized, expected_b64)
      match_b64url = Crypto::Subtle.constant_time_compare(normalized, expected_b64url)
      match_b64url_pad = Crypto::Subtle.constant_time_compare(normalized, expected_b64url_pad)

      match_hex || match_b64 || match_b64url || match_b64url_pad
    end

    # Verifies an asymmetric signature (Ed25519, RSA PKCS#1 v1.5 / PSS, or ECDSA DER / raw P1363)
    # against `challenge`.
    def verify_asymmetric?(
      challenge : String,
      response : String,
      public_key : String,
      algorithm : String? = nil,
    ) : Bool
      return false if challenge.empty? || response.empty? || public_key.empty?

      signatures = decode_signatures(response.strip)
      return false if signatures.empty?

      alg = algorithm.try(&.downcase.strip)

      case alg
      when "ed25519", "eddsa"
        verify_ed25519?(challenge, signatures, public_key)
      when .try(&.starts_with?("rs")), .try(&.starts_with?("ps")), "rsa"
        verify_rsa?(challenge, signatures, public_key, alg)
      when .try(&.starts_with?("es")), "ecdsa", "ec"
        verify_ecdsa?(challenge, signatures, public_key, alg)
      else
        verify_ed25519?(challenge, signatures, public_key) ||
          verify_ecdsa?(challenge, signatures, public_key, alg) ||
          verify_rsa?(challenge, signatures, public_key, alg)
      end
    end

    def verify_ed25519?(challenge : String, signatures : Array(Bytes), public_key : String) : Bool
      pub_bytes = extract_ed25519_public_key(public_key.strip)
      return false unless pub_bytes && pub_bytes.size == 32

      message = challenge.to_slice
      signatures.any? do |sig|
        next false unless sig.size == 64
        verified_slice = begin
          Ed25519.verify(sig, message, pub_bytes)
        rescue
          false
        end
        next true if verified_slice

        if challenge.size.even? && challenge.matches?(/\A[0-9a-fA-F]+\z/)
          begin
            Ed25519.verify(sig, challenge.hexbytes, pub_bytes)
          rescue
            false
          end
        else
          false
        end
      end
    end

    def verify_rsa?(
      challenge : String,
      signatures : Array(Bytes),
      public_key : String,
      algorithm : String? = nil,
    ) : Bool
      return false unless public_key.includes?("BEGIN")
      # Avoid treating an EC PRIVATE KEY PEM as RSA
      return false if public_key.includes?("EC PRIVATE KEY")

      rsa = OpenSSL::PKey::RSA.new(public_key)
      digests = digest_names_for(algorithm)

      signatures.any? do |sig|
        digests.any? do |digest_name|
          verified_pkcs1 = begin
            rsa.verify(OpenSSL::Digest.new(digest_name), sig, challenge)
          rescue
            false
          end
          next true if verified_pkcs1

          {% if compare_versions(LibCrypto::OPENSSL_VERSION, "3.0.0") >= 0 %}
            begin
              rsa.verify_pss(OpenSSL::Digest.new(digest_name), sig, challenge)
            rescue
              false
            end
          {% else %}
            false
          {% end %}
        end
      end
    rescue
      false
    end

    def verify_ecdsa?(
      challenge : String,
      signatures : Array(Bytes),
      public_key : String,
      algorithm : String? = nil,
    ) : Bool
      ec = load_ec_key(public_key.strip)
      return false unless ec

      digest_name = ec_digest_name(ec, algorithm)
      digest_bytes = OpenSSL::Digest.new(digest_name).update(challenge).final
      coord_size = (ec.group_degree + 7) // 8

      signatures.any? do |sig|
        verified_der = begin
          ec.ec_verify(digest_bytes, sig)
        rescue
          false
        end
        next true if verified_der

        if sig.size == coord_size * 2
          begin
            asn1_sig = JWT.raw_to_asn1(sig, ec)
            ec.ec_verify(digest_bytes, asn1_sig)
          rescue
            false
          end
        else
          false
        end
      end
    rescue
      false
    end

    private def decode_signatures(encoded : String) : Array(Bytes)
      results = [] of Bytes

      if encoded.size.even? && encoded.matches?(/\A[0-9a-fA-F]+\z/)
        begin
          results << encoded.hexbytes
        rescue
        end
      end

      begin
        decoded = Base64.decode(encoded)
        results << decoded unless decoded.empty? || results.includes?(decoded)
      rescue Base64::Error
      end

      results
    end

    private def extract_ed25519_public_key(key : String) : Bytes?
      if key.size == 64 && key.matches?(/\A[0-9a-fA-F]{64}\z/)
        return key.hexbytes
      end

      if key.starts_with?("-----BEGIN")
        if match = key.match(/-----BEGIN [A-Z ]+-----(.+?)-----END [A-Z ]+-----/m)
          der = Base64.decode(match[1])
          if der.size == 44 && der[0, 12] == ED25519_SPKI_PREFIX
            return der[12, 32]
          end
        end
        return
      end

      decoded = Base64.decode(key)
      decoded if decoded.size == 32
    rescue
      nil
    end

    private def load_ec_key(key : String) : OpenSSL::PKey::EC?
      if key.starts_with?("-----BEGIN")
        return if key.includes?("RSA ")
        ec = OpenSSL::PKey::EC.new(key)
        # Ensure the loaded key actually has a valid EC group
        ec.group_degree > 0 ? ec : nil
      elsif key.size == 130 && key.starts_with?("04") && key.matches?(/\A[0-9a-fA-F]+\z/)
        OpenSSL::PKey::EC.from_public_bytes(key.hexbytes, "P-256")
      end
    rescue
      nil
    end

    private def ec_digest_name(ec : OpenSSL::PKey::EC, algorithm : String?) : String
      case algorithm
      when "es384" then "sha384"
      when "es512" then "sha512"
      when "es256", "es256k"
        "sha256"
      else
        case ec.group_degree
        when 384 then "sha384"
        when 521 then "sha512"
        else          "sha256"
        end
      end
    end

    private def digest_names_for(algorithm : String?) : Array(String)
      case algorithm
      when "rs256", "ps256" then ["sha256"]
      when "rs384", "ps384" then ["sha384"]
      when "rs512", "ps512" then ["sha512"]
      else                       ["sha256", "sha384", "sha512"]
      end
    end

    private def hmac_digest_symbol(algorithm : String) : OpenSSL::Algorithm
      case algorithm
      when "hs384", "hmac-sha384" then OpenSSL::Algorithm::SHA384
      when "hs512", "hmac-sha512" then OpenSSL::Algorithm::SHA512
      else                             OpenSSL::Algorithm::SHA256
      end
    end
  end
end
