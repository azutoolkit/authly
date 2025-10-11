module Authly
  module ResponseHelper
    def self.write(context, status_code, content_type = "text/plain", body = "")
      context.response.status_code = status_code
      context.response.content_type = content_type
      context.response.print body
    end

    def self.redirect(context, location)
      context.response.status_code = 302
      context.response.headers["Location"] = location
    end
  end
end
