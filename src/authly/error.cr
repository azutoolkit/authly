module Authly
  ERROR_MSG = {
    invalid_redirect_uri:   "Invalid redirect uri",
    invalid_state:          "Invalid state",
    invalid_scope:          "Invalid scope value in the request",
    invalid_client:         "Client authentication failed, such as if the request contains an invalid client ID or secret.",
    owner_credentials:      "Invalid owner credentials",
    invalid_request:        "The request is missing a parameter so the server can’t proceed with the request",
    invalid_grant:          "The authorization code is invalid or expired.",
    unauthorized_client:    "This client is not authorized to use the requested grant type",
    unsupported_grant_type: "Invalid or unknown grant type",
    access_denied:          "The user or authorization server denied the request",
  }

  module Error
    extend self

    def owner_credentials
      raise OAuthError(400).new(:owner_credentials)
    end

    def unsupported_grant_type
      raise OAuthError(400).new(:unsupported_grant_type)
    end

    def unauthorized_client
      raise OAuthError(401).new(:unauthorized_client)
    end

    def invalid_redirect_uri
      raise OAuthError(400).new(:invalid_redirect_uri)
    end

    def invalid_state
      raise OAuthError(400).new(:invalid_state)
    end

    def invalid_grant
      raise OAuthError(400).new(:invalid_grant)
    end

    def invalid_scope
      raise OAuthError(400).new(:invalid_scope)
    end

    def bad_request(type : Symbol)
      raise OAuthError(400).new(type)
    end
  end

  class OAuthError(Code) < Exception
    getter code : Int32 = Code
    getter type : Symbol

    def initialize(@type)
      super "#{ERROR_MSG[@type]}"
    end
  end
end
