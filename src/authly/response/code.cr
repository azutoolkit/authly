module Authly
  module Response
    struct Code
      include JSON::Serializable

      getter state : String, code : String

      def initialize(@code : String, @state : String)
      end
    end
  end
end
