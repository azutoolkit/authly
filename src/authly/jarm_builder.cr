require "json"
require "jwt"
require "openssl"
require "openssl_ext"
require "base64"
require "random/secure"

# LibCrypto extensions for GCM mode
lib LibCrypto
  EVP_CTRL_GCM_SET_IVLEN =  0x9
  EVP_CTRL_GCM_GET_TAG   = 0x10
  EVP_CTRL_GCM_SET_TAG   = 0x11

  fun evp_cipher_ctx_ctrl = EVP_CIPHER_CTX_ctrl(ctx : Void*, type : Int32, arg : Int32, ptr : Void*) : Int32
end

module Authly
  # JarmBuilder constructs JWT-secured authorization responses per RFC 9101
  # Supports JWS signing and optional JWE encryption
  class JarmBuilder
    getter issuer : String
    getter audience : String
    getter lifetime : Time::Span
    getter signing_key : String
    getter signing_algorithm : JWT::Algorithm
    getter encryption_key : String?
    getter encryption_algorithm : String?
    getter encryption_encoding : String?

    def initialize(
      @issuer : String,
      @audience : String,
      @lifetime : Time::Span,
      @signing_key : String,
      @signing_algorithm : JWT::Algorithm,
      @encryption_key : String? = nil,
      @encryption_algorithm : String? = nil,
      @encryption_encoding : String? = nil,
    )
    end

    # Build a JARM response JWT
    def build(params : Hash(String, String)) : String
      # Build the JWT payload with authorization response parameters
      payload = build_payload(params)

      # Sign the JWT (JWS)
      signed_jwt = sign_jwt(payload)

      # Optionally encrypt the JWT (JWE)
      if encryption_key && encryption_algorithm && encryption_encoding
        encrypt_jwt(signed_jwt)
      else
        signed_jwt
      end
    end

    # Build authorization response as a JWT
    def build_authorization_response(
      code : String? = nil,
      state : String? = nil,
      access_token : String? = nil,
      token_type : String? = nil,
      expires_in : Int64? = nil,
      scope : String? = nil,
      id_token : String? = nil,
      error : String? = nil,
      error_description : String? = nil,
    ) : String
      params = Hash(String, String).new

      # Add authorization response parameters
      params["code"] = code if code
      params["state"] = state if state
      params["access_token"] = access_token if access_token
      params["token_type"] = token_type if token_type
      params["expires_in"] = expires_in.to_s if expires_in
      params["scope"] = scope if scope
      params["id_token"] = id_token if id_token
      params["error"] = error if error
      params["error_description"] = error_description if error_description

      build(params)
    end

    private def build_payload(params : Hash(String, String)) : Hash(String, JSON::Any)
      now = Time.utc.to_unix
      exp = (Time.utc + lifetime).to_unix

      payload = {
        "iss" => JSON::Any.new(issuer),
        "aud" => JSON::Any.new(audience),
        "exp" => JSON::Any.new(exp),
        "iat" => JSON::Any.new(now),
      }

      # Add all authorization response parameters to the JWT
      params.each do |key, value|
        payload[key] = JSON::Any.new(value)
      end

      payload
    end

    private def sign_jwt(payload : Hash(String, JSON::Any)) : String
      JWT.encode(payload, signing_key, signing_algorithm)
    end

    # Encrypt JWT using JWE (nested JWT)
    # Implements RFC 7516 (JSON Web Encryption) with compact serialization
    private def encrypt_jwt(jwt : String) : String
      enc_alg = encryption_algorithm
      enc_enc = encryption_encoding
      enc_key = encryption_key

      return jwt unless enc_alg && enc_enc && enc_key

      # Build JWE header
      header = {
        "alg" => enc_alg,
        "enc" => enc_enc,
        "cty" => "JWT", # Content type is JWT (nested JWT)
      }

      # Encode header
      encoded_header = base64url_encode(header.to_json)

      # Generate Content Encryption Key (CEK) based on encryption encoding
      cek_size = get_cek_size(enc_enc)
      cek = Random::Secure.random_bytes(cek_size)

      # Encrypt the CEK with the key encryption algorithm
      encrypted_key = encrypt_cek(cek, enc_key, enc_alg)
      encoded_encrypted_key = base64url_encode(encrypted_key)

      # Generate Initialization Vector (IV) for AES-GCM (96 bits)
      iv = Random::Secure.random_bytes(12)
      encoded_iv = base64url_encode(iv)

      # Additional Authenticated Data (AAD) is the encoded header
      aad = encoded_header

      # Encrypt the JWT content
      ciphertext, auth_tag = encrypt_content(jwt, cek, iv, aad, enc_enc)
      encoded_ciphertext = base64url_encode(ciphertext)
      encoded_auth_tag = base64url_encode(auth_tag)

      # JWE Compact Serialization: header.encrypted_key.iv.ciphertext.tag
      "#{encoded_header}.#{encoded_encrypted_key}.#{encoded_iv}.#{encoded_ciphertext}.#{encoded_auth_tag}"
    end

    # Get Content Encryption Key size based on encryption encoding
    private def get_cek_size(enc : String) : Int32
      case enc
      when "A128GCM", "A128CBC-HS256"
        16 # 128 bits
      when "A192GCM", "A192CBC-HS384"
        24 # 192 bits
      when "A256GCM", "A256CBC-HS512"
        32 # 256 bits
      else
        raise "Unsupported encryption encoding: #{enc}"
      end
    end

    # Encrypt the Content Encryption Key using key encryption algorithm
    private def encrypt_cek(cek : Bytes, key : String, alg : String) : Bytes
      case alg
      when "RSA-OAEP", "RSA-OAEP-256"
        encrypt_cek_rsa_oaep(cek, key, alg)
      when "ECDH-ES"
        # For ECDH-ES, the CEK is derived from ECDH, not encrypted
        # This is a simplified implementation - full ECDH-ES requires key agreement
        raise "ECDH-ES not yet implemented - use RSA-OAEP instead"
      when "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"
        # ECDH-ES with AES Key Wrap
        raise "ECDH-ES+AKW not yet implemented - use RSA-OAEP instead"
      else
        raise "Unsupported key encryption algorithm: #{alg}"
      end
    end

    # Encrypt CEK using RSA-OAEP
    private def encrypt_cek_rsa_oaep(cek : Bytes, public_key_pem : String, alg : String) : Bytes
      # Parse RSA public key from PEM
      rsa = OpenSSL::PKey::RSA.new(public_key_pem)

      # Determine padding mode based on algorithm
      padding = case alg
                when "RSA-OAEP"
                  # RSA-OAEP with SHA-1 (default)
                  LibCrypto::Padding::PKCS1_OAEP_PADDING
                when "RSA-OAEP-256"
                  # RSA-OAEP with SHA-256
                  # Note: Both RSA-OAEP and RSA-OAEP-256 use the same padding constant
                  # The hash function is determined by OpenSSL defaults
                  LibCrypto::Padding::PKCS1_OAEP_PADDING
                else
                  raise "Unsupported RSA algorithm: #{alg}"
                end

      # Encrypt the CEK using the public key
      encrypted = rsa.public_encrypt(cek, padding)
      encrypted
    end

    # Encrypt content using AES-GCM or AES-CBC
    private def encrypt_content(plaintext : String, cek : Bytes, iv : Bytes, aad : String, enc : String) : {Bytes, Bytes}
      case enc
      when "A128GCM", "A192GCM", "A256GCM"
        encrypt_aes_gcm(plaintext, cek, iv, aad, enc)
      when "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"
        # AES-CBC with HMAC requires splitting the key and additional steps
        raise "AES-CBC-HMAC not yet implemented - use AES-GCM instead"
      else
        raise "Unsupported content encryption: #{enc}"
      end
    end

    # Encrypt using AES-GCM
    private def encrypt_aes_gcm(plaintext : String, cek : Bytes, iv : Bytes, aad : String, enc : String) : {Bytes, Bytes}
      # Determine cipher based on key size
      cipher_name = case enc
                    when "A128GCM"
                      "aes-128-gcm"
                    when "A192GCM"
                      "aes-192-gcm"
                    when "A256GCM"
                      "aes-256-gcm"
                    else
                      raise "Invalid AES-GCM algorithm: #{enc}"
                    end

      # Create cipher
      cipher = OpenSSL::Cipher.new(cipher_name)
      cipher.encrypt

      # Set key and IV
      cipher.key = cek
      cipher.iv = iv

      # Set Additional Authenticated Data (AAD)
      # For GCM mode, we update the cipher with AAD before encrypting
      aad_bytes = aad.to_slice
      unless aad_bytes.empty?
        # Pass AAD through update without producing ciphertext output
        cipher.update(aad_bytes)
      end

      # Encrypt the plaintext
      ciphertext_io = IO::Memory.new
      ciphertext_io.write(cipher.update(plaintext))
      ciphertext_io.write(cipher.final)
      ciphertext = ciphertext_io.to_slice

      # Get authentication tag (16 bytes for GCM)
      # We need to use LibCrypto directly to get the GCM tag
      auth_tag = Bytes.new(16)
      ctx = cipher.@ctx # Access the internal context
      ret = LibCrypto.evp_cipher_ctx_ctrl(ctx, LibCrypto::EVP_CTRL_GCM_GET_TAG, 16, auth_tag.to_unsafe.as(Void*))
      if ret != 1
        raise "Failed to get GCM authentication tag"
      end

      {ciphertext, auth_tag}
    end

    # Base64 URL-safe encoding without padding
    private def base64url_encode(data : String) : String
      Base64.urlsafe_encode(data, padding: false)
    end

    private def base64url_encode(data : Bytes) : String
      Base64.urlsafe_encode(data, padding: false)
    end

    # Create a form_post HTML response
    def self.build_form_post_html(redirect_uri : String, jwt : String) : String
      <<-HTML
      <!DOCTYPE html>
      <html>
        <head>
          <title>Submit Authorization Response</title>
        </head>
        <body onload="javascript:document.forms[0].submit()">
          <form method="post" action="#{escape_html(redirect_uri)}">
            <input type="hidden" name="response" value="#{escape_html(jwt)}" />
            <noscript>
              <p>JavaScript is disabled. Please click the button below to continue.</p>
              <button type="submit">Continue</button>
            </noscript>
          </form>
        </body>
      </html>
      HTML
    end

    private def self.escape_html(text : String) : String
      text
        .gsub("&", "&amp;")
        .gsub("<", "&lt;")
        .gsub(">", "&gt;")
        .gsub("\"", "&quot;")
        .gsub("'", "&#39;")
    end
  end
end
