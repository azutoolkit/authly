require "http/client"
require "uri"

module Authly
  module Social
    record HttpResponse, status_code : Int32, body : String, headers : HTTP::Headers = HTTP::Headers.new

    module HttpClient
      abstract def post_form(
        url : String,
        params : Hash(String, String),
        headers : HTTP::Headers = HTTP::Headers.new,
      ) : HttpResponse

      abstract def get(
        url : String,
        headers : HTTP::Headers = HTTP::Headers.new,
      ) : HttpResponse
    end

    class StdlibHttpClient
      include HttpClient

      MAX_BODY_BYTES = 1_048_576

      property connect_timeout : Time::Span
      property read_timeout : Time::Span

      def initialize(
        @connect_timeout : Time::Span = 10.seconds,
        @read_timeout : Time::Span = 10.seconds,
      )
      end

      def post_form(
        url : String,
        params : Hash(String, String),
        headers : HTTP::Headers = HTTP::Headers.new,
      ) : HttpResponse
        uri = URI.parse(url)
        req_headers = headers.dup
        req_headers["Content-Type"] ||= "application/x-www-form-urlencoded"
        req_headers["Accept"] ||= "application/json"
        req_headers["User-Agent"] ||= "Authly-SocialClient/1.0"
        body = URI::Params.encode(params)

        with_client(uri) do |client|
          path = uri.request_target
          client.post(path, headers: req_headers, body: body) do |response|
            read_bounded_response(response)
          end
        end
      rescue IO::Error | Socket::Error
        raise Error.invalid_grant
      end

      def get(
        url : String,
        headers : HTTP::Headers = HTTP::Headers.new,
      ) : HttpResponse
        uri = URI.parse(url)
        req_headers = headers.dup
        req_headers["Accept"] ||= "application/json"
        req_headers["User-Agent"] ||= "Authly-SocialClient/1.0"

        with_client(uri) do |client|
          path = uri.request_target
          client.get(path, headers: req_headers) do |response|
            read_bounded_response(response)
          end
        end
      rescue IO::Error | Socket::Error
        raise Error.invalid_grant
      end

      private def with_client(uri : URI, & : HTTP::Client -> HttpResponse) : HttpResponse
        client = HTTP::Client.new(uri)
        client.connect_timeout = @connect_timeout
        client.read_timeout = @read_timeout
        begin
          yield client
        ensure
          client.close
        end
      end

      private def read_bounded_response(response : HTTP::Client::Response) : HttpResponse
        io = response.body_io
        buffer = IO::Memory.new
        bytes_copied = IO.copy(io, buffer, MAX_BODY_BYTES + 1)
        raise Error.invalid_grant if bytes_copied > MAX_BODY_BYTES
        HttpResponse.new(response.status_code, buffer.to_s, response.headers)
      end
    end
  end
end
