require "http/server"

# The verified claims of the request, set by `Authly::Handler::Bearer`.
#
# They live in an instance variable of the request's own context, so concurrent requests (one
# fiber each) never share them and nothing global has to be cleaned up when the request ends.
class HTTP::Server::Context
  property authly_claims : Authly::Claims?
end
