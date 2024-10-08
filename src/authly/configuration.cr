module Authly
  # Security Configuration
  class SecurityConfiguration
    property secret_key : String = Random::Secure.hex(16)
    property public_key : String = Random::Secure.hex(16)
    property algorithm : JWT::Algorithm = JWT::Algorithm::HS256
  end

  # Time-To-Live Configuration
  class TTLConfiguration
    property refresh_ttl : Time::Span = 1.day
    property code_ttl : Time::Span = 5.minutes
    property access_ttl : Time::Span = 1.hour
  end

  # Providers Configuration
  class ProvidersConfiguration
    property owners : AuthorizableOwner = Owners.new
    property clients : AuthorizableClient = Clients.new
    property jti_provider : JTIProvider = InMemoryJTIProvider.new
  end

  # Configuration class using Singleton and Builder Pattern
  class Configuration
    property issuer : String = "The Authority Server Provider"
    property security : SecurityConfiguration = SecurityConfiguration.new
    property ttl : TTLConfiguration = TTLConfiguration.new
    property providers : ProvidersConfiguration = ProvidersConfiguration.new
    property token_type : String = "jwt"

    # Singleton instance
    @@instance : Configuration?

    def self.instance : Configuration
      @@instance ||= Configuration.new
    end

    def initialize
    end

    # Builder for Configuration
    class Builder
      def initialize
        @configuration = Configuration.new
      end

      def issuer(issuer : String) : self
        @configuration.issuer = issuer
        self
      end

      def security(security : SecurityConfiguration) : self
        @configuration.security = security
        self
      end

      def ttl(ttl : TTLConfiguration) : self
        @configuration.ttl = ttl
        self
      end

      def owner_client(owner_client : ProvidersConfiguration) : self
        @configuration.owner_client = owner_client
        self
      end

      def build : Configuration
        Configuration.instance
      end
    end
  end
end
