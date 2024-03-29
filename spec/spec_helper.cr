require "spec"
require "digest"
require "base64"
require "faker"
require "../src/authly"

# Configure
secret_key = Random::Secure.hex(16)
Authly.configure do |c|
  c.secret_key = secret_key
  c.public_key = secret_key
end

Authly.clients << Authly::Client.new("example", "secret", "https://www.example.com/callback", "1")
Authly.owners << Authly::Owner.new("username", "password")
