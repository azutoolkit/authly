require "http/server"
require "../../src/authly"
require "./settings"

server = HTTP::Server.new([
  Authly::Handler.new,
])
server.bind_tcp "0.0.0.0", 4000
puts "Listening on http://0.0.0.0:4000"

server.listen
