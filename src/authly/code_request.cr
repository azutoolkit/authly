module Authly
  struct CodeRequest
    getter :client_id, :redirect_uri, :scope, :state, :authorized

    def initialize(
      response_type : String,
      @client_id : String,
      @redirect_uri : URI,
      @scope : String = "",
      @state : String = "",
      @authorized : Bool = false
    )
      @response_type = ResponseType.parse response_type
    end

    def valid?
      !@redirect_uri.nil? & !@redirect_uri.host.nil?
    end
  end
end
