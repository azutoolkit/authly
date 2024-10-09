require "http/server"
require "./spec_helper"

server = HTTP::Server.new([
  Authly::OAuthHandler.new,
])
server.bind_tcp "127.0.0.1", 8080
server.listen
