module Authly
  struct Token
    def self.write(cid, uri = "", exp = 30.seconds.from_now.to_unix, state = "", scope = "")
      new(cid, uri, exp, state, scope).to_s
    end

    def self.matches!(code, request)
      read(code).matches! request
    end

    def self.read(code)
      payload = JWT.decode(code, Authly.secret, JWT::Algorithm::HS256).first
      new payload["cid"].to_s,
        payload["uri"].to_s,
        payload["exp"].to_s.to_i64,
        payload["state"].to_s,
        payload["scope"].to_s
    end

    getter cid : String
    getter exp : Int64 = 30.seconds.from_now.to_unix
    getter uri : String
    getter state : String = ""
    getter scope : String = ""

    def initialize(@cid, @uri, @exp, @state, @scope)
    end

    def to_s
      JWT.encode(to_h, Authly.secret, JWT::Algorithm::HS256)
    end

    private def to_h
      {"cid" => cid, "uri" => uri, "exp" => exp, "state" => state, "scope" => scope}
    end
  end
end
