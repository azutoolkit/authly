require "uri"

module Authly
  # What a dynamic registration may ask for (RFC 7591), judged against the host's allow-lists
  # (`registration_grant_types`, `registration_response_types`, `registration_scopes`).
  class RegistrationPolicy
    record Violation, error : String, description : String

    MAX_REDIRECT_URIS =   10
    MAX_URI_LENGTH    = 2048
    LOOPBACK_HOSTS    = {"localhost", "127.0.0.1", "::1"}

    # An exact redirect URI the client can safely be sent back to (RFC 8252, OAuth 2.0 Security BCP): https, http on
    # a loopback host, or a private-use scheme named after a domain (`com.example.app:/cb`). No fragment, user info,
    # wildcard, blank or control character, so it can only ever match itself.
    def self.redirect_uri?(value : String) : Bool
      return false unless plain?(value)
      uri = URI.parse(value)
      return false if uri.user || uri.password
      scheme = uri.scheme.try(&.downcase)
      case scheme
      when nil     then false
      when "https" then !uri.host.to_s.empty?
      when "http"  then LOOPBACK_HOSTS.includes?(uri.hostname.to_s.downcase)
      else              private_scheme?(scheme)
      end
    rescue URI::Error
      false
    end

    # A page or document the registration points at (client home page, logo, policy): https only.
    def self.https_uri?(value : String) : Bool
      return false unless plain?(value)
      uri = URI.parse(value)
      uri.scheme.try(&.downcase) == "https" && !uri.host.to_s.empty? && uri.user.nil? && uri.password.nil?
    rescue URI::Error
      false
    end

    private def self.plain?(value : String) : Bool
      return false if value.empty? || value.size > MAX_URI_LENGTH || value.includes?('#')
      value.each_char.none? { |char| char.control? || char.whitespace? || char == '*' }
    end

    private def self.private_scheme?(scheme : String) : Bool
      scheme.includes?('.') && scheme.matches?(/\A[a-z][a-z0-9+.\-]*\z/)
    end

    def initialize(@config : Configuration = Authly.config)
    end

    # The first rule `client` breaks, nil when it breaks none.
    def violation(client : DynamicClient) : Violation?
      grant_violation(client) || response_type_violation(client) || scope_violation(client) ||
        metadata_uri_violation(client) || redirect_violation(client)
    end

    private def redirect_violation(client : DynamicClient) : Violation?
      uris = client.redirect_uris
      return if uris.size <= MAX_REDIRECT_URIS && uris.all? { |uri| self.class.redirect_uri?(uri) }
      Violation.new("invalid_redirect_uri",
        "redirect_uris must be 1 to #{MAX_REDIRECT_URIS} exact https, loopback http or private-use scheme URIs without fragment or wildcard")
    end

    private def metadata_uri_violation(client : DynamicClient) : Violation?
      uris = [client.client_uri, client.logo_uri, client.tos_uri, client.policy_uri, client.jwks_uri].compact
      return if uris.all? { |uri| self.class.https_uri?(uri) }
      Violation.new("invalid_client_metadata", "client_uri, logo_uri, tos_uri, policy_uri and jwks_uri must be https URIs")
    end

    private def grant_violation(client : DynamicClient) : Violation?
      return if client.grant_types.all? { |grant| @config.registration_grant_types.includes?(grant) }
      Violation.new("invalid_client_metadata", "grant_types must be among: #{@config.registration_grant_types.join(", ")}")
    end

    private def response_type_violation(client : DynamicClient) : Violation?
      return if client.response_types.all? { |type| @config.registration_response_types.includes?(type) }
      Violation.new("invalid_client_metadata", "response_types must be among: #{@config.registration_response_types.join(", ")}")
    end

    private def scope_violation(client : DynamicClient) : Violation?
      requested = client.scope.to_s.split(' ', remove_empty: true)
      return if requested.all? { |scope| @config.registration_scopes.includes?(scope) }
      Violation.new("invalid_client_metadata", "scope must be among: #{@config.registration_scopes.join(", ")}")
    end
  end
end
