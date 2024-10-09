module Authly
  ERROR_MSG = {
    invalid_redirect_uri:   "Invalid redirect uri",
    invalid_state:          "Invalid state",
    invalid_scope:          "Invalid scope value in the request",
    invalid_client:         "Client authentication failed, such as if the request contains an invalid client ID or secret.",
    invalid_request:        "The request is missing a parameter so the server can’t proceed with the request",
    invalid_grant:          "The authorization code is invalid or expired.",
    invalid_response_type:  "The response type is invalid.",
    owner_credentials:      "Invalid owner credentials",
    unauthorized_client:    "This client is not authorized to use the requested grant type",
    unsupported_grant_type: "Invalid or unknown grant type",
    access_denied:          "The user or authorization server denied the request",
    unsupported_token_type: "The authorization server does not support the revocation of the presented token type",
    invalid_token:          "The token is invalid or expired",
  }

  class Error(Code) < Exception
    def self.invalid_token
      raise Error(400).new(:invalid_token)
    end

    def self.unsupported_token_type
      raise Error(400).new(:unsupported_token_type)
    end

    def self.owner_credentials
      raise Error(400).new(:owner_credentials)
    end

    def self.unsupported_grant_type
      raise Error(400).new(:unsupported_grant_type)
    end

    def self.unauthorized_client
      raise Error(401).new(:unauthorized_client)
    end

    def self.invalid_redirect_uri
      raise Error(400).new(:invalid_redirect_uri)
    end

    def self.invalid_state
      raise Error(400).new(:invalid_state)
    end

    def self.invalid_grant
      raise Error(400).new(:invalid_grant)
    end

    def self.invalid_scope
      raise Error(400).new(:invalid_scope)
    end

    def self.invalid_response_type
      raise Error(400).new(:invalid_response_type)
    end

    def self.bad_request(type : Symbol)
      raise Error(400).new(type)
    end

    getter code : Int32 = Code
    getter type : Symbol

    def initialize(@type)
      super "#{ERROR_MSG[@type]}"
    end
  end
end
