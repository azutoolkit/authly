require "spec"
require "../src/authly"

# Configure

Authly.configure do |c|
  c.secret = "Some Secret"

  c.client = ->validate_client(String, String?, String?)

  c.owner = ->(username : String, password : String) do
    username == "username" && password == "password"
  end
end

def validate_client(client_id : String, client_secret : String? = nil, redirect_uri : String? = nil) : Bool
  if !client_secret.nil? && !redirect_uri.nil?
    client_id == "1" && client_secret == "secret" && redirect_uri == "https://www.example.com/callback"
  elsif !client_secret.nil?
    client_id == "1" && client_secret == "secret"
  else
    client_id == "1" && redirect_uri == "https://www.example.com/callback"
  end
end
