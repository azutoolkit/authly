require "spec"
require "../src/authly"

# Configure
Authly.client = ->(client_id : String, client_secret : String, redirect_uri : String?) do
  if !redirect_uri.nil?
    client_id == "1" && client_secret == "secret" && redirect_uri == "https://www.example.com/callback"
  else
    client_id == "1" && client_secret == "secret"
  end
end

Authly.owner = ->(username : String, password : String) do
  username == "username" && password == "password"
end

def build_temporary_code(
  response_type = "code",
  client_id = "1",
  redirect_uri = URI.parse("https://www.examples.com/callback"),
  scope = "",
  state = "",
  authorized = false
)
  Authly::CodeRequest.new(
    response_type: response_type,
    client_id: client_id,
    redirect_uri: redirect_uri,
    scope: scope,
    state: state,
    authorized: authorized
  )
end
