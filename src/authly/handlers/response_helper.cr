require "base64"
require "openssl"

module Authly
  module ResponseHelper
    def self.write(context, status_code, content_type = "text/plain", body = "")
      context.response.status_code = status_code
      context.response.content_type = content_type
      # A HEAD response has no body: bytes written anyway are read as the start of the next response
      # on a kept-alive connection. It still advertises the length a GET would have.
      if context.request.method == "HEAD"
        context.response.content_length = body.to_s.bytesize
      else
        context.response.print body
      end
    end

    # An HTML page for the browser (consent, device verification): not framable, not cacheable, no
    # scripts or external loads, no referrer. Every value interpolated into `html` must be escaped.
    # `script_src` is the exact text of the one inline script the page may run (allowed by its hash).
    def self.write_page(context, status_code, html, script_src : String? = nil)
      headers = context.response.headers
      script = script_src ? " script-src 'sha256-#{Base64.strict_encode(OpenSSL::Digest.new("SHA256").update(script_src).final)}';" : ""
      headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline';#{script} base-uri 'none'; frame-ancestors 'none'"
      headers["X-Frame-Options"] = "DENY"
      headers["X-Content-Type-Options"] = "nosniff"
      headers["Cache-Control"] = "no-store"
      headers["Referrer-Policy"] = "no-referrer"
      write(context, status_code, "text/html; charset=utf-8", html)
    end

    def self.redirect(context, location)
      context.response.status_code = 302
      context.response.headers["Location"] = location
    end
  end
end
