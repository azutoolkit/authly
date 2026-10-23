module Authly
  # The verified claims of an access token, as downstream code sees them.
  struct Claims
    getter payload : Hash(String, JSON::Any)

    def initialize(@payload : Hash(String, JSON::Any))
    end

    def self.from(payload : Hash) : Claims
      claims = {} of String => JSON::Any
      payload.each { |key, value| claims[key.to_s] = value.is_a?(JSON::Any) ? value : JSON::Any.new(value) }
      new(claims)
    end

    def [](name : String) : JSON::Any
      @payload[name]
    end

    def []?(name : String) : JSON::Any?
      @payload[name]?
    end

    def subject : String?
      self["sub"]?.try(&.as_s?)
    end

    def client_id : String?
      self["cid"]?.try(&.as_s?)
    end

    def id : String?
      self["jti"]?.try(&.as_s?)
    end

    def scopes : Array(String)
      (self["scope"]?.try(&.as_s?) || "").split(' ', remove_empty: true)
    end

    def scope?(scope : String) : Bool
      scopes.includes?(scope)
    end

    def all_scopes?(required : Enumerable(String)) : Bool
      granted = scopes
      required.all? { |scope| granted.includes?(scope) }
    end

    def any_scope?(candidates : Enumerable(String)) : Bool
      granted = scopes
      candidates.any? { |scope| granted.includes?(scope) }
    end

    def audience?(audience : String) : Bool
      case raw = self["aud"]?.try(&.raw)
      when String then raw == audience
      when Array  then raw.any? { |value| value.as_s? == audience }
      else             false
      end
    end
  end
end
