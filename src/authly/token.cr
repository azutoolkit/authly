module Authly
  struct Token
    getter cid : String
    getter exp : Int64 = 30.seconds.from_now.to_unix
    getter uri : String = ""
    getter state : String = ""
    getter scope : String = ""

    def initialize(code : String)
      data = JWT.decode(code, Authly.secret, JWT::Algorithm::HS256).first
      @cid = data["cid"].to_s
      @uri = data["uri"].to_s
      @exp = data["exp"].to_s.to_i64
      @state = data["state"].to_s
      @scope = data["scope"].to_s
    end

    def initialize(@cid, @exp, @uri = "", @state = "", @scope = "")
    end

    def to_s
      JWT.encode(to_h, Authly.secret, JWT::Algorithm::HS256)
    end

    private def to_h
      {"cid" => cid, "uri" => uri, "exp" => exp, "state" => state, "scope" => scope}
    end
  end
end
