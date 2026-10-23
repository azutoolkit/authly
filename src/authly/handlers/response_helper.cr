module Authly
  module ResponseHelper
    def self.write(context, status_code, content_type = "text/plain", body = "")
      context.response.status_code = status_code
      context.response.content_type = content_type
      # A HEAD response has no body: bytes written anyway are read as the start of the next response
      # on a kept-alive connection.
      context.response.print body unless context.request.method == "HEAD"
    end

    def self.redirect(context, location)
      context.response.status_code = 302
      context.response.headers["Location"] = location
    end
  end
end
