# Shared examples that any implementation of Authly's store interfaces can run, so an adapter (Redis, SQL, ...)
# proves it behaves like the in-memory stores Authly ships. In a spec file:
#
# ```
# require "spec"
# require "authly"
# require "authly/conformance"
#
# Authly::Stores::Conformance.token_store("MyTokenStore") { MyTokenStore.new(DB.open(ENV["DATABASE_URL"])) }
# ```
#
# The block builds the store under test; it is called once per example. The examples write random ids only, so they
# can share a database with other data.
require "spec"
require "./authly"
require "./authly_conformance/*"
