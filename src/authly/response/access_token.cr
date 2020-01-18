module Authly
  module Response
    struct AccessToken
      include JSON::Serializable

      getter access_token : String
      getter token_type : String = "Bearer"
      getter expires_in : Int64 = 1.hour.from_now.to_unix

      @[JSON::Field(emit_null: false)]
      getter id_token : String? = nil

      @[JSON::Field(emit_null: false)]
      getter refresh_token : String?

      def initialize(client_id)
        @access_token = Authly::Token::Access.new(client_id).to_s
        @refresh_token = Authly::Token::Refresh.new(client_id).to_s
      end
    end
  end
end
