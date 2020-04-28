module Authly
  class Configuration
    property secret_key : String = "JWT SECRET KEY"
    property refresh_ttl : Time::Span = 1.day
    property code_ttl : Time::Span = 3.minutes
    property access_ttl : Time::Span = 1.hour
    property owners : AuthorizableOwner = Owners.new
    property clients : AuthorizableClient = Clients.new
  end
end
