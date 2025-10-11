module Authly
  class DeviceVerificationHandler
    def self.handle(context)
      case context.request.method
      when "GET"
        handle_get(context)
      when "POST"
        handle_post(context)
      else
        ResponseHelper.write(context, 405, "text/plain", "Method not allowed")
      end
    end

    private def self.handle_get(context)
      user_code = context.request.query_params["user_code"]?

      # Render device verification page
      ResponseHelper.write(context, 200, "text/html", render_verification_page(user_code))
    end

    private def self.handle_post(context)
      params = context.request.form_params
      user_code = params.fetch("user_code", "").upcase.gsub(/[^A-Z0-9\-]/, "")
      user_id = params.fetch("user_id", "")
      action = params.fetch("action", "")

      # Fetch device code data by user code
      device_data = Authly.config.device_code_store.fetch_by_user_code(user_code)

      unless device_data
        ResponseHelper.write(context, 400, "text/html", render_error_page("Invalid or expired user code"))
        return
      end

      if action == "approve"
        # Mark device code as verified
        device_data.verified = true
        device_data.user_id = user_id
        Authly.config.device_code_store.update(device_data.device_code, device_data)

        ResponseHelper.write(context, 200, "text/html", render_success_page)
      elsif action == "deny"
        # Delete the device code
        Authly.config.device_code_store.delete(device_data.device_code)

        ResponseHelper.write(context, 200, "text/html", render_denied_page)
      else
        ResponseHelper.write(context, 400, "text/plain", "Invalid action")
      end
    rescue e : KeyError
      ResponseHelper.write(context, 400, "text/html", render_error_page(e.message || "Missing required parameter"))
    end

    private def self.render_verification_page(user_code : String? = nil)
      <<-HTML
      <html>
        <head>
          <title>Device Verification</title>
          <style>
            body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }
            input[type="text"] { width: 100%; padding: 10px; font-size: 16px; margin: 10px 0; }
            button { padding: 10px 20px; margin: 5px; font-size: 16px; cursor: pointer; }
            .approve { background-color: #4CAF50; color: white; border: none; }
            .deny { background-color: #f44336; color: white; border: none; }
          </style>
        </head>
        <body>
          <h1>Device Verification</h1>
          <p>Enter the code shown on your device:</p>
          <form action="/device" method="post">
            <input type="text" name="user_code" placeholder="XXXX-XXXX" value="#{user_code}" required autofocus pattern="[A-Z0-9-]{9}">
            <input type="text" name="user_id" placeholder="User ID (for testing)" required>
            <div>
              <button type="submit" name="action" value="approve" class="approve">Approve</button>
              <button type="submit" name="action" value="deny" class="deny">Deny</button>
            </div>
          </form>
        </body>
      </html>
      HTML
    end

    private def self.render_success_page
      <<-HTML
      <html>
        <head>
          <title>Success</title>
          <style>
            body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; text-align: center; }
            .success { color: #4CAF50; font-size: 48px; }
          </style>
        </head>
        <body>
          <div class="success">✓</div>
          <h1>Device Authorized!</h1>
          <p>You can now close this window and return to your device.</p>
        </body>
      </html>
      HTML
    end

    private def self.render_denied_page
      <<-HTML
      <html>
        <head>
          <title>Access Denied</title>
          <style>
            body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; text-align: center; }
            .error { color: #f44336; font-size: 48px; }
          </style>
        </head>
        <body>
          <div class="error">✗</div>
          <h1>Access Denied</h1>
          <p>You have denied access to this device.</p>
        </body>
      </html>
      HTML
    end

    private def self.render_error_page(message : String)
      <<-HTML
      <html>
        <head>
          <title>Error</title>
          <style>
            body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }
            .error { color: #f44336; }
          </style>
        </head>
        <body>
          <h1 class="error">Error</h1>
          <p>#{message}</p>
          <a href="/device">Try again</a>
        </body>
      </html>
      HTML
    end
  end
end
