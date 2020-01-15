module Authly
  class TemporaryCode
    include JSON::Serializable

    @[JSON::Field(emit_null: false)]
    getter state : String? = nil
    getter code : String

    def initialize(data : CodeRequest)
      @code = token(data).to_s
      @state = data.state
    end

    private def token(data : CodeRequest)
      Authly.token_provider.new data.client_id,
        1.minute.from_now.to_unix,
        data.redirect_uri.to_s,
        data.state.to_s,
        data.scope
    end
  end
end
