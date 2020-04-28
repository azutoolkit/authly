require "spec"
require "../src/authly"

# Configure
Authly.configure do |c|
  c.secret_key = "Some Secret"
end

Authly.clients << Authly::Client.new("example", "secret", "https://www.example.com/callback", "1")
Authly.owners << Authly::Owner.new("username", "password")
