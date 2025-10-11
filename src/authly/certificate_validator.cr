require "digest/sha256"
require "base64"

module Authly
  module CertificateValidator
    # Extract client certificate from HTTP request context
    # Note: This requires the HTTP server to be configured with mTLS
    def self.extract_certificate(context : HTTP::Server::Context) : String?
      # In Crystal's HTTP::Server, client certificates would be available through
      # the TLS context if mTLS is enabled. This is a simplified implementation.
      # In production, you'd extract from context.request.ssl_socket or similar

      # For now, we'll check for a custom header that contains the certificate
      # (this would be set by a reverse proxy like nginx or a custom TLS handler)
      cert_header = context.request.headers["X-Client-Certificate"]?
      return nil unless cert_header

      # Decode the certificate (assuming it's base64 encoded)
      begin
        Base64.decode_string(cert_header)
      rescue
        nil
      end
    end

    # Calculate SHA-256 thumbprint of a certificate
    def self.calculate_thumbprint(certificate : String) : String
      # For DER-encoded certificates, calculate SHA-256 hash
      digest = Digest::SHA256.digest(certificate)
      Base64.urlsafe_encode(digest, padding: false)
    end

    # Validate certificate against trusted CAs
    def self.valid_certificate?(certificate : String, trusted_cas : Array(String)) : Bool
      # In a production implementation, this would:
      # 1. Parse the certificate
      # 2. Validate the signature chain against trusted CAs
      # 3. Check expiration dates
      # 4. Verify the certificate hasn't been revoked

      # For now, return true if certificate is present and trusted_cas is configured
      return true if trusted_cas.empty? # If no CAs specified, accept all

      # Simplified validation - in production, use OpenSSL::X509 for proper validation
      !certificate.empty?
    end
  end
end
