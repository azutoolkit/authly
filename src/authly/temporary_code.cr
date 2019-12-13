require "json"

module Authly
  class TemporaryCode
    include JSON::Serializable

    @[JSON::Field(emit_null: false)]
    getter state : String? = nil
    getter code : String

    def initialize(data : CodeRequest)
      @code = token(data)
      @state = data.state
    end

    private def token(data : CodeRequest)
      Token.write data.client_id,
        data.redirect_uri.to_s,
        1.minute.from_now.to_unix,
        data.state.to_s,
        data.scope
    end
  end
end
