require "html"

module Authly
  # The page where a signed-in resource owner approves or denies a device. The owner is the one
  # `Authly.config.authenticate_user` returns; the form never names the approving user, and carries a
  # signed token (see `FormToken`) bound to that owner as its anti-CSRF token.
  class DeviceVerificationHandler
    DEVICE = "device"

    def self.handle(context)
      authenticator = Authly.config.authenticate_user
      return not_configured(context) unless authenticator

      case context.request.method
      when "GET"
        handle_get(context, authenticator)
      when "POST"
        handle_post(context, authenticator)
      else
        ResponseHelper.write(context, 405, "text/plain", "Method not allowed")
      end
    end

    private def self.not_configured(context)
      Log.error { "Authly.config.authenticate_user is not set: the device verification page refuses every request" }
      ResponseHelper.write(context, 500, "text/plain",
        "Device verification is not configured: set Authly.config.authenticate_user")
    end

    private def self.handle_get(context, authenticator)
      subject = signed_in_subject(context, authenticator)
      return unless subject

      user_code = context.request.query_params["user_code"]?
      page = render_verification_page(context.request.path, user_code, pending_request(user_code), form_token(subject))
      ResponseHelper.write_page(context, 200, page)
    end

    private def self.handle_post(context, authenticator)
      subject = signed_in_subject(context, authenticator)
      return unless subject
      return unless valid_form?(context, subject)

      params = context.request.form_params
      user_code = params.fetch("user_code", "").upcase.gsub(/[^A-Z0-9\-]/, "")
      device_data = Authly.config.device_code_store.fetch_by_user_code(user_code)

      unless device_data
        ResponseHelper.write_page(context, 400, render_error_page("Invalid or expired user code"))
        return
      end

      case params.fetch("action", "")
      when "approve" then approve(context, device_data, subject)
      when "deny"    then deny(context, device_data)
      else                ResponseHelper.write(context, 400, "text/plain", "Invalid action")
      end
    end

    private def self.approve(context, device_data, subject : String)
      device_data.verified = true
      device_data.user_id = subject
      Authly.config.device_code_store.update(device_data.device_code, device_data)

      ResponseHelper.write_page(context, 200, render_success_page)
    end

    private def self.deny(context, device_data)
      Authly.config.device_code_store.delete(device_data.device_code)

      ResponseHelper.write_page(context, 200, render_denied_page)
    end

    # The token must be genuine, issued to this very owner and not used before.
    private def self.valid_form?(context, subject : String) : Bool
      claims = FormToken.verify(DEVICE, context.request.form_params.fetch("csrf_token", ""))
      status = form_status(claims, subject)
      return true unless status

      ResponseHelper.write(context, status, "text/plain", "Invalid or expired form token")
      false
    end

    private def self.form_status(claims : Hash(String, String)?, subject : String) : Int32?
      return 400 unless claims
      return 403 unless claims["subject"]? == subject

      nonce = claims["nonce"]?
      return 400 unless nonce && Authly.config.state_store.consume(nonce)

      nil
    end

    private def self.form_token(subject : String) : String
      nonce = Random::Secure.hex(16)
      Authly.config.state_store.store(nonce, Authly.config.consent_ttl)
      FormToken.issue(DEVICE, {"subject" => subject, "nonce" => nonce}, Authly.config.consent_ttl)
    end

    private def self.signed_in_subject(context, authenticator) : String?
      subject = authenticator.call(context).try(&.strip).presence
      return subject if subject

      if login_url = Authly.config.login_url
        ResponseHelper.redirect(context, login_url.call(context))
      else
        ResponseHelper.write(context, 401, "application/json", {
          error:             "login_required",
          error_description: "The resource owner must sign in",
        }.to_json)
      end
      nil
    end

    # The device authorization behind a user code, so the owner sees what they are approving (RFC 8628 5.4)
    private def self.pending_request(user_code : String?) : DeviceCodeData?
      return unless user_code
      data = Authly.config.device_code_store.fetch_by_user_code(user_code.upcase.gsub(/[^A-Z0-9\-]/, ""))
      data unless data.nil? || data.expired?
    end

    private def self.request_details(data : DeviceCodeData?) : String
      return "" unless data
      "<p>Client: #{HTML.escape(data.client_id)}</p>\n            <p>Requested Scopes: #{HTML.escape(data.scope)}</p>"
    end

    private def self.render_verification_page(path : String, user_code : String?, pending : DeviceCodeData?, csrf_token : String)
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
            #{request_details(pending)}
            <form action="#{HTML.escape(path)}" method="post">
              <input type="hidden" name="csrf_token" value="#{HTML.escape(csrf_token)}">
              <input type="text" name="user_code" placeholder="XXXX-XXXX" value="#{HTML.escape(user_code.to_s)}" required autofocus pattern="[A-Z0-9-]{9}">
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
            <p>#{HTML.escape(message)}</p>
            <a href="/device">Try again</a>
          </body>
        </html>
        HTML
    end
  end
end
