module Authly
  class Handler
    # Which requests a handler applies to. By default all of them; `except` lists paths that
    # are let through (a health check), `prefixes` narrows the handler to an allowlist.
    #
    # Paths are compared whole-segment, after percent-decoding, collapsing `//` and resolving `.`
    # and `..`, so `/%61pi/x`, `//api/x` and `/x/../api/x` are all `/api/x`. A path that cannot
    # be decoded is protected. `prefixes` match case-insensitively (`/API/x` is protected by
    # `/api`: the safe direction for a router that ignores case), `except` matches exactly
    # (`/HEALTH` is not skipped by `/health`). An entry covers its subpaths, and a trailing slash
    # does not matter (`/api/` covers `/api`).
    struct PathFilter
      @prefixes : Array(String)?
      @except : Array(String)

      def initialize(prefixes : Array(String)? = nil, except : Array(String) = [] of String)
        raise ArgumentError.new("An empty prefixes list would protect nothing") if prefixes.try(&.empty?)

        @prefixes = prefixes.try(&.map { |prefix| PathFilter.entry(prefix).downcase })
        @except = except.map { |path| PathFilter.entry(path) }
      end

      protected def self.entry(path : String) : String
        normalize(path) || raise ArgumentError.new("Invalid path: #{path.inspect}")
      end

      def protects?(path : String) : Bool
        normalized = PathFilter.normalize(path)
        return true if normalized.nil?

        listed?(normalized.downcase, @prefixes, true) && !listed?(normalized, @except, false)
      end

      def self.normalize(path : String) : String?
        segments = [] of String
        URI.decode(path).tr("\\", "/").split('/') do |segment|
          case segment
          when "", "." then next
          when ".."    then segments.pop?
          else              segments << segment
          end
        end
        "/#{segments.join('/')}"
      rescue URI::Error
        nil
      end

      private def listed?(path : String, entries : Array(String)?, default : Bool) : Bool
        return default if entries.nil?

        entries.any? { |entry| entry == "/" || path == entry || path.starts_with?("#{entry}/") }
      end
    end
  end
end
