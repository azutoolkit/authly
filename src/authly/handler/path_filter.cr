module Authly
  class Handler
    # Which requests a handler applies to. By default all of them; `except` lists paths that
    # are let through (a health check), `prefixes` narrows the handler to an allowlist.
    #
    # Paths are compared whole-segment, after percent-decoding, collapsing `//` and resolving `.`
    # and `..`, so `/%61pi/x`, `//api/x` and `/x/../api/x` are all `/api/x`. A path that cannot
    # be decoded is protected. `prefixes` match case-insensitively (`/API/x` is protected by
    # `/api`: the safe direction for a router that ignores case), `except` and `exact` match
    # case-sensitively (`/HEALTH` is not skipped by `/health`). A trailing slash does not matter
    # (`/api/` covers `/api`).
    #
    # `except` is a **segment-prefix** match: `/health` also exempts `/health/anything`. `exact` exempts
    # only the path itself (`/health`, `/health/`), which is the safer choice for a health endpoint.
    #
    # The path is decoded once, as a router does. A path that still contains `%` afterwards (double
    # encoding, an invalid escape such as `%zz`) or a NUL byte is not understood, so it is protected.
    struct PathFilter
      @prefixes : Array(String)?
      @except : Array(String)
      @exact : Array(String)

      def initialize(prefixes : Array(String)? = nil, except : Array(String) = [] of String, exact : Array(String) = [] of String)
        raise ArgumentError.new("An empty prefixes list would protect nothing") if prefixes.try(&.empty?)

        @prefixes = prefixes.try(&.map { |prefix| PathFilter.entry(prefix).downcase })
        @except = except.map { |path| PathFilter.entry(path) }
        @exact = exact.map { |path| PathFilter.entry(path) }
      end

      protected def self.entry(path : String) : String
        raise ArgumentError.new("Invalid path: #{path.inspect}") if path.includes?('%')

        normalize(path) || raise ArgumentError.new("Invalid path: #{path.inspect}")
      end

      def protects?(path : String) : Bool
        normalized = PathFilter.normalize(path)
        return true if normalized.nil?

        listed?(normalized.downcase, @prefixes, true) && !listed?(normalized, @except, false) && !@exact.includes?(normalized)
      end

      def self.normalize(path : String) : String?
        decoded = URI.decode(path)
        return if decoded.includes?('%') || decoded.includes?('\0')

        segments = [] of String
        decoded.tr("\\", "/").split('/') do |segment|
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
