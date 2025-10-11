require "json"
require "random"

module Authly
  # Represents a dynamically registered OAuth2 client per RFC 7591
  struct DynamicClient
    include JSON::Serializable

    # Required fields
    getter client_id : String

    @[JSON::Field(emit_null: false)]
    getter client_secret : String?

    getter redirect_uris : Array(String)

    # Optional metadata fields
    @[JSON::Field(emit_null: false)]
    getter client_name : String?

    @[JSON::Field(emit_null: false)]
    getter client_uri : String?

    @[JSON::Field(emit_null: false)]
    getter logo_uri : String?

    getter grant_types : Array(String)
    getter response_types : Array(String)

    @[JSON::Field(emit_null: false)]
    getter token_endpoint_auth_method : String?

    @[JSON::Field(emit_null: false)]
    getter scope : String?

    @[JSON::Field(emit_null: false)]
    getter contacts : Array(String)?

    @[JSON::Field(emit_null: false)]
    getter tos_uri : String?

    @[JSON::Field(emit_null: false)]
    getter policy_uri : String?

    @[JSON::Field(emit_null: false)]
    getter jwks_uri : String?

    @[JSON::Field(emit_null: false)]
    getter software_id : String?

    @[JSON::Field(emit_null: false)]
    getter software_version : String?

    # Registration metadata
    getter client_id_issued_at : Int64

    @[JSON::Field(emit_null: false)]
    getter client_secret_expires_at : Int64?

    def initialize(
      @client_id : String,
      @client_secret : String?,
      @redirect_uris : Array(String),
      @grant_types : Array(String) = ["authorization_code"],
      @response_types : Array(String) = ["code"],
      @token_endpoint_auth_method : String? = "client_secret_basic",
      @client_name : String? = nil,
      @client_uri : String? = nil,
      @logo_uri : String? = nil,
      @scope : String? = nil,
      @contacts : Array(String)? = nil,
      @tos_uri : String? = nil,
      @policy_uri : String? = nil,
      @jwks_uri : String? = nil,
      @software_id : String? = nil,
      @software_version : String? = nil,
      @client_id_issued_at : Int64 = Time.utc.to_unix,
      @client_secret_expires_at : Int64? = nil,
    )
    end

    # Create from registration request
    def self.from_registration_request(params : Hash(String, JSON::Any)) : DynamicClient
      # Generate client credentials
      client_id = "client_#{Random::Secure.hex(16)}"

      # Determine if client needs a secret
      auth_method = params["token_endpoint_auth_method"]?.try(&.as_s) || "client_secret_basic"
      client_secret = (auth_method == "none") ? nil : Random::Secure.hex(32)

      # Extract redirect URIs (required)
      redirect_uris = params["redirect_uris"]?.try(&.as_a.map(&.as_s)) || [] of String
      raise Error(400).new(:invalid_request) if redirect_uris.empty?

      # Extract grant types with defaults
      grant_types = params["grant_types"]?.try(&.as_a.map(&.as_s)) || ["authorization_code"]

      # Extract response types with defaults
      response_types = params["response_types"]?.try(&.as_a.map(&.as_s)) || ["code"]

      # Extract optional metadata
      client_name = params["client_name"]?.try(&.as_s)
      client_uri = params["client_uri"]?.try(&.as_s)
      logo_uri = params["logo_uri"]?.try(&.as_s)
      scope = params["scope"]?.try(&.as_s)
      contacts = params["contacts"]?.try(&.as_a.map(&.as_s))
      tos_uri = params["tos_uri"]?.try(&.as_s)
      policy_uri = params["policy_uri"]?.try(&.as_s)
      jwks_uri = params["jwks_uri"]?.try(&.as_s)
      software_id = params["software_id"]?.try(&.as_s)
      software_version = params["software_version"]?.try(&.as_s)

      new(
        client_id: client_id,
        client_secret: client_secret,
        redirect_uris: redirect_uris,
        grant_types: grant_types,
        response_types: response_types,
        token_endpoint_auth_method: auth_method,
        client_name: client_name,
        client_uri: client_uri,
        logo_uri: logo_uri,
        scope: scope,
        contacts: contacts,
        tos_uri: tos_uri,
        policy_uri: policy_uri,
        jwks_uri: jwks_uri,
        software_id: software_id,
        software_version: software_version
      )
    end

    # Validate the client metadata
    def valid? : Bool
      return false if redirect_uris.empty?
      return false if grant_types.empty?
      return false if response_types.empty?

      # Validate URIs if present
      redirect_uris.each do |uri|
        return false unless valid_uri?(uri)
      end

      if uri = client_uri
        return false unless valid_uri?(uri)
      end
      if uri = logo_uri
        return false unless valid_uri?(uri)
      end
      if uri = tos_uri
        return false unless valid_uri?(uri)
      end
      if uri = policy_uri
        return false unless valid_uri?(uri)
      end
      if uri = jwks_uri
        return false unless valid_uri?(uri)
      end

      # Validate grant types are supported
      supported_grants = [
        "authorization_code",
        "implicit",
        "password",
        "client_credentials",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code",
      ]
      grant_types.each do |grant|
        return false unless supported_grants.includes?(grant)
      end

      # Validate response types are supported
      supported_response_types = ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token", "none"]
      response_types.each do |response_type|
        return false unless supported_response_types.includes?(response_type)
      end

      # Validate token endpoint auth method
      if method = token_endpoint_auth_method
        supported_auth_methods = ["client_secret_basic", "client_secret_post", "none"]
        return false unless supported_auth_methods.includes?(method)
      end

      true
    end

    private def valid_uri?(uri : String) : Bool
      parsed = URI.parse(uri)
      !parsed.scheme.nil? && !parsed.host.nil?
    rescue
      false
    end
  end
end
