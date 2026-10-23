require "http/server"

module Authly
  # Raised by `context.authly_claims!` when no verified claims are there.
  class MissingClaims < Exception
    def initialize
      super("No verified claims: Authly::Handler::Bearer has to run before this handler and cover this path")
    end
  end
end

# The verified claims of the request, set by `Authly::Handler::Bearer`.
#
# They live in an instance variable of the request's own context, so concurrent requests (one
# fiber each) never share them and nothing global has to be cleaned up when the request ends.
class HTTP::Server::Context
  property authly_claims : Authly::Claims?

  # The claims, or `Authly::MissingClaims` when `Bearer` did not authenticate this request.
  def authly_claims! : Authly::Claims
    authly_claims || raise Authly::MissingClaims.new
  end
end
