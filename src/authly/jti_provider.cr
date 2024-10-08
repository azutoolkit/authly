module Authly
  module JTIProvider
    abstract def revoke(jti : String)
    abstract def revoked?(jti : String) : Bool
  end
end
