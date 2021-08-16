module Authly
  struct Refresh
    def initialize(@client_id = String)
    end

    def jwt
      JWT.encode({
        "cid" => client_id,
        "exp" => REFRESH_TTL.from_now.to_unix,
      }, SECRET, JWT::Algorithm::HS256)
    end

    def to_s
      jwt.to_s
    end
  end
end
