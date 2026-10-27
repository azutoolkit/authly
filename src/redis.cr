# Redis-backed stores: `require "authly/redis"` after `require "authly"`. Nothing here is compiled into an app that
# does not require it, and nothing connects until a store is used.
require "redis"
require "digest/sha256"
require "./authly"
require "./authly_redis/*"
