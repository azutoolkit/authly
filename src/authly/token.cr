module Authly
  module Token
    SECRET      = Authly.config.secret
    CODE_TTL    = Authly.config.code_ttl
    ACCESS_TTL  = Authly.config.access_ttl
    REFRESH_TTL = Authly.config.refresh_ttl

    def self.decode(code : String)
      JWT.decode(code, SECRET, JWT::Algorithm::HS256)
    end

    struct Code
      def initialize(cid, uri, state = "", scope = "")
        @value = JWT.encode({
          "cid" => cid, "uri" => uri, "state" => state, "scope" => scope, "exp" => CODE_TTL.from_now.to_unix,
        }, SECRET, JWT::Algorithm::HS256)
      end

      def to_s
        @value.to_s
      end
    end

    struct Access
      def initialize(client_id)
        @value = JWT.encode(
          {"cid" => client_id, "exp" => ACCESS_TTL.from_now.to_unix}, SECRET, JWT::Algorithm::HS256)
      end

      def to_s
        @value.to_s
      end
    end

    struct Refresh
      def initialize(client_id)
        @value = JWT.encode(
          {"cid" => client_id, "exp" => REFRESH_TTL.from_now.to_unix}, SECRET, JWT::Algorithm::HS256
        )
      end

      def to_s
        @value.to_s
      end
    end
  end
end
