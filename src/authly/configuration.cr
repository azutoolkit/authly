module Authly
  class Configuration
    property secret : String = "SOME SECRET KEY"
    property client : Proc(String, String?, String?, Bool) = ->(client_id : String, client_secret : String?, redirect_uri : String?) { true }
    property owner : Proc(String, String, Bool) = ->(username : String, password : String) { true }
    property refresh_ttl : Time::Span = 1.day
    property code_ttl : Time::Span = 3.minutes
    property access_ttl : Time::Span = 1.hour
  end
end
