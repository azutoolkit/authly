secret_key = "4bce37fbb1542a68dddba2da22635beca9d814cb3424c461fcc8876904ad39c1"

PORT        = 3000
BASE_URI    = "http://0.0.0.0:#{PORT}"
STATE_STORE = Authly::InMemoryStateStore.new

Authly.configure do |config|
  config.secret_key = secret_key
  config.public_key = secret_key
  config.state_store = STATE_STORE
  # The signed-in owner of a spec request is named by this header (stands in for the host's session)
  config.authenticate_user = ->(context : HTTP::Server::Context) { context.request.headers["X-Test-User"]?.presence }
end

Authly.clients << Authly::Client.new("example", "secret", "https://www.example.com/callback", "1", "read write admin openid", "authorization_code client_credentials password refresh_token implicit")
Authly.clients << Authly::Client.new("test_client", "test_secret", "https://example.com/callback", "test_client", "read write admin openid profile email", "authorization_code client_credentials password refresh_token implicit")
Authly.owners << Authly::Owner.new("username", "password")
Authly.owners << Authly::Owner.new("john", "secret")

OAUTH_HANDLER = Authly::Handler.new
