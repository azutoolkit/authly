module Authly
  class_property token_provider : Token.class = JWTToken

  record TokenClaims, cid : String?, exp : Int64?,
    uri : String?, state : String?, scope : String?,

    abstract class Token
      getter claims : TokenClaims

      def initialize(@claims : TokenClaims)
      end

      abstract def initialize(code : String) : self
      abstract def to_s : String
    end

  class JWTToken < Token
    def initialize(code : String) : self
      data = JWT.decode(code, Authly.secret, JWT::Algorithm::HS256).first
      @cid = data["cid"].to_s
      @uri = data["uri"].to_s
      @exp = data["exp"].to_s.to_i64
      @state = data["state"].to_s
      @scope = data["scope"].to_s
      self
    end

    def initialize(claims : TokenClaims)
    end

    def to_s : String
      JWT.encode(to_h, Authly.secret, JWT::Algorithm::HS256)
    end
  end
end
