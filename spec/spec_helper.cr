require "spec"
require "../src/authly"

# Load Clients
Authly.clients << Authly::Client.new("example", "secret", "https://www.example.com/callback", "1")

# Configure
Authly.configure do |c|
  c.secret = "Some Secret"
  c.owner = ->(username : String, password : String) do
    username == "username" && password == "password"
  end
end
