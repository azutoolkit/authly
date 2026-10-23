require "http/server"
require "./challenge"
require "./path_filter"

module Authly
  class Handler
    # Lets a request through only when the token `Bearer` verified grants the scopes: all of
    # `all` and at least one of `any` (an empty list asks nothing). Otherwise 403 `insufficient_scope`
    # with the required scopes in the challenge; without verified claims (no `Bearer` before it)
    # the request is refused with 401, never let through.
    #
    # ```
    # users = Authly::Handler::RequireScope.all("read:users", prefixes: ["/users"])
    # admin = Authly::Handler::RequireScope.any("admin", "root", prefixes: ["/admin"])
    #
    # Applies to every path unless narrowed (`prefixes:` is an allowlist, `except:` lists open paths);
    # see `PathFilter`.
    # HTTP::Server.new([bearer, users, admin, app])
    # ```
    class RequireScope
      include HTTP::Handler

      getter realm : String

      def initialize(
        @all : Array(String) = [] of String,
        @any : Array(String) = [] of String,
        realm : String = "authly",
        prefixes : Array(String)? = nil,
        except : Array(String) = [] of String,
      )
        raise ArgumentError.new("RequireScope needs at least one scope") if @all.empty? && @any.empty?

        (@all + @any).each { |scope| Handler.header_token!(scope, "scope") }
        @realm = Handler.header_token!(realm, "realm")
        @paths = PathFilter.new(prefixes, except)
      end

      def self.all(*scopes : String, realm : String = "authly", prefixes : Array(String)? = nil, except : Array(String) = [] of String) : RequireScope
        new(all: scopes.to_a, realm: realm, prefixes: prefixes, except: except)
      end

      def self.any(*scopes : String, realm : String = "authly", prefixes : Array(String)? = nil, except : Array(String) = [] of String) : RequireScope
        new(any: scopes.to_a, realm: realm, prefixes: prefixes, except: except)
      end

      def call(context : HTTP::Server::Context)
        return call_next(context) unless @paths.protects?(context.request.path)

        claims = context.authly_claims
        if claims.nil?
          Challenge.invalid_token(@realm).write(context)
        elsif permits?(claims)
          call_next(context)
        else
          Challenge.insufficient_scope(@realm, (@all + @any).uniq.join(' ')).write(context)
        end
      end

      private def permits?(claims : Claims) : Bool
        claims.all_scopes?(@all) && (@any.empty? || claims.any_scope?(@any))
      end
    end
  end
end
