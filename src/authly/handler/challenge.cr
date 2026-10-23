module Authly
  class Handler
    # An RFC 6750 error response: the status, the `WWW-Authenticate: Bearer` challenge and a JSON body.
    struct Challenge
      DESCRIPTIONS = {
        "invalid_request"    => "The request is malformed",
        "invalid_token"      => "The access token is invalid, expired or revoked",
        "insufficient_scope" => "The access token does not grant the required scope",
      }

      getter status : Int32
      getter error : String?
      getter scope : String?

      def initialize(@realm : String, @status : Int32, @error : String? = nil, @scope : String? = nil)
      end

      def self.missing(realm : String) : Challenge
        new(realm, 401)
      end

      def self.invalid_request(realm : String) : Challenge
        new(realm, 400, "invalid_request")
      end

      def self.invalid_token(realm : String) : Challenge
        new(realm, 401, "invalid_token")
      end

      def self.insufficient_scope(realm : String, scope : String) : Challenge
        new(realm, 403, "insufficient_scope", scope)
      end

      def header : String
        String.build do |io|
          io << "Bearer realm=\"" << @realm << '"'
          @error.try { |error| io << ", error=\"" << error << '"' }
          @scope.try { |scope| io << ", scope=\"" << scope << '"' }
        end
      end

      def write(context : HTTP::Server::Context) : Nil
        context.response.headers["WWW-Authenticate"] = header
        context.response.headers["Cache-Control"] = "no-store"
        body = @error.try { |error| {error: error, error_description: DESCRIPTIONS[error]}.to_json } || "{}"
        ResponseHelper.write(context, @status, "application/json", body)
      end
    end

    # Header-safe: no quotes, backslashes, whitespace or control characters could split a challenge.
    # :nodoc:
    def self.header_token!(value : String, what : String) : String
      raise ArgumentError.new("Invalid #{what}: #{value.inspect}") unless value.matches?(/\A[\x21\x23-\x5B\x5D-\x7E]+\z/)
      value
    end
  end
end
