secret_key = "4bce37fbb1542a68dddba2da22635beca9d814cb3424c461fcc8876904ad39c1"
Authly.configure do |config|
  config.secret_key = secret_key
  config.public_key = secret_key
end

Authly.clients << Authly::Client.new("example", "secret", "https://www.example.com/callback", "1")
Authly.owners << Authly::Owner.new("username", "password")
