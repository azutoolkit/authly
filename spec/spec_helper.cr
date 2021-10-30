require "spec"
require "digest"
require "base64"
require "../src/authly"

# Configure
Authly.configure do |c|
  c.secret_key = Random::Secure.hex(16)
end

Authly.clients << Authly::Client.new("example", "secret", "https://www.example.com/callback", "1")
Authly.owners << Authly::Owner.new("username", "password")
