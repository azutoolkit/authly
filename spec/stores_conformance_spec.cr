require "./spec_helper"
require "../src/conformance"

# The in-memory stores define the contracts the shared examples check.
Authly::Stores::Conformance.token_store("InMemoryStore") { Authly::InMemoryStore.new }
Authly::Stores::Conformance.state_store("InMemoryStateStore") { Authly::InMemoryStateStore.new }
