require "http/server"
require "../../src/authly"
require "./settings"

server = HTTP::Server.new([
  Authly::Handler.new,
])

server.bind_tcp "0.0.0.0", PORT
puts "Listening on http://0.0.0.0:#{PORT}"

server.listen
