module Authly
  module TokenBinder
    # Extract certificate thumbprint from token claims
    def self.extract_thumbprint(token_data : Hash(String, JSON::Any)) : String?
      cnf = token_data["cnf"]?
      return unless cnf

      # Handle both Hash and JSON::Any types
      case cnf.raw
      when Hash
        cnf_hash = cnf.as_h
        thumbprint = cnf_hash["x5t#S256"]?
        return thumbprint.as_s if thumbprint
      end

      nil
    rescue
      nil
    end

    # Verify that the current certificate matches the token binding
    def self.verify_binding(context : HTTP::Server::Context, token_data : Hash(String, JSON::Any)) : Bool
      # Skip verification if certificate binding is not required
      return true unless Authly.config.require_certificate_bound_tokens

      # Extract the thumbprint from token
      bound_thumbprint = extract_thumbprint(token_data)
      return true unless bound_thumbprint # Token is not bound, allow it

      # Extract certificate from current request
      certificate = CertificateValidator.extract_certificate(context)
      return false unless certificate # Certificate required but not provided

      # Calculate thumbprint of current certificate
      current_thumbprint = CertificateValidator.calculate_thumbprint(certificate)

      # Compare thumbprints
      bound_thumbprint == current_thumbprint
    end
  end
end
