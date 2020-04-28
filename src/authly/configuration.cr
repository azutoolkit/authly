module Authly
  class Configuration
    property secret : String = "SOME SECRET KEY"
    property owner : Proc(String, String, Bool) = ->(username : String, password : String) { true }
    property refresh_ttl : Time::Span = 1.day
    property code_ttl : Time::Span = 3.minutes
    property access_ttl : Time::Span = 1.hour
  end
end
