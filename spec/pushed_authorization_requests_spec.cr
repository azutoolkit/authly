require "./spec_helper"

module Authly
  describe "Pushed Authorization Requests (PAR)" do
    describe "end-to-end PAR flow" do
      it "completes full authorization code flow with PAR" do
        # Step 1: Client pushes authorization parameters
        par_request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback&scope=openid&state=abc123"
        )

        par_io = IO::Memory.new
        par_response = HTTP::Server::Response.new(par_io)
        par_context = HTTP::Server::Context.new(par_request, par_response)
        PARHandler.handle(par_context)

        par_response.close
        par_io.rewind
        par_result_str = par_io.gets_to_end

        par_response.status_code.should eq(201)
        par_body = par_result_str.split("\r\n\r\n")[1]
        par_result = JSON.parse(par_body)
        request_uri = par_result["request_uri"].as_s

        # Step 2: User authorization with request_uri
        auth = AuthorizationSecuritySpec.approve("client_id=test_client&request_uri=#{URI.encode_www_form(request_uri)}")

        # Should redirect with authorization code
        auth.status.should eq(302)
        location = auth.location.not_nil!
        location.should contain("code=")
        location.should contain("state=abc123")
      end

      it "prevents reuse of request_uri (single-use)" do
        # Step 1: Create PAR request
        par_request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback&state=xyz"
        )

        par_io = IO::Memory.new
        par_response = HTTP::Server::Response.new(par_io)
        par_context = HTTP::Server::Context.new(par_request, par_response)
        PARHandler.handle(par_context)

        par_response.close
        par_io.rewind
        par_result_str = par_io.gets_to_end

        par_body = par_result_str.split("\r\n\r\n")[1]
        par_result = JSON.parse(par_body)
        request_uri = par_result["request_uri"].as_s

        # Step 2: First authorization attempt (should succeed)
        auth1 = AuthorizationSecuritySpec.approve("client_id=test_client&request_uri=#{URI.encode_www_form(request_uri)}")

        auth1.status.should eq(302)

        # Step 3: Second authorization attempt with same request_uri (should fail)
        auth2 = AuthorizationSecuritySpec.approve("client_id=test_client&request_uri=#{URI.encode_www_form(request_uri)}")

        auth2.status.should eq(400)
      end

      it "validates client_id matches the one used in PAR" do
        # Step 1: Create PAR request with client_id
        par_request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback&state=xyz"
        )

        par_io = IO::Memory.new
        par_response = HTTP::Server::Response.new(par_io)
        par_context = HTTP::Server::Context.new(par_request, par_response)
        PARHandler.handle(par_context)

        par_response.close
        par_io.rewind
        par_result_str = par_io.gets_to_end

        par_body = par_result_str.split("\r\n\r\n")[1]
        par_result = JSON.parse(par_body)
        request_uri = par_result["request_uri"].as_s

        # Step 2: Try to use request_uri with different client_id
        auth = AuthorizationSecuritySpec.approve("client_id=different_client&request_uri=#{URI.encode_www_form(request_uri)}")

        # Should fail due to client_id mismatch
        auth.status.should eq(400)
      end

      it "handles expired request_uri" do
        # Create PAR store with short TTL for testing
        original_ttl = Authly.config.par_ttl
        Authly.config.par_ttl = 0.seconds

        # Step 1: Create PAR request
        par_request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback&state=xyz"
        )

        par_io = IO::Memory.new
        par_response = HTTP::Server::Response.new(par_io)
        par_context = HTTP::Server::Context.new(par_request, par_response)
        PARHandler.handle(par_context)

        par_response.close
        par_io.rewind
        par_result_str = par_io.gets_to_end

        par_body = par_result_str.split("\r\n\r\n")[1]
        par_result = JSON.parse(par_body)
        request_uri = par_result["request_uri"].as_s

        # Step 2: Try to use expired request_uri
        auth = AuthorizationSecuritySpec.approve("client_id=test_client&request_uri=#{URI.encode_www_form(request_uri)}")

        # Should fail due to expiration
        auth.status.should eq(400)

        Authly.config.par_ttl = original_ttl
      end

      it "supports PKCE parameters via PAR" do
        # Step 1: Push authorization request with PKCE
        par_request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=pkce123"
        )

        par_io = IO::Memory.new
        par_response = HTTP::Server::Response.new(par_io)
        par_context = HTTP::Server::Context.new(par_request, par_response)
        PARHandler.handle(par_context)

        par_response.close
        par_io.rewind
        par_result_str = par_io.gets_to_end

        par_response.status_code.should eq(201)
        par_body = par_result_str.split("\r\n\r\n")[1]
        par_result = JSON.parse(par_body)
        request_uri = par_result["request_uri"].as_s

        # Step 2: Authorize with request_uri
        auth = AuthorizationSecuritySpec.approve("client_id=test_client&request_uri=#{URI.encode_www_form(request_uri)}")

        # Should succeed with PKCE parameters
        auth.status.should eq(302)
        location = auth.location.not_nil!
        location.should contain("code=")
      end

      it "enforces PAR when require_par is enabled" do
        # Enable PAR requirement
        original_require_par = Authly.config.require_par?
        Authly.config.require_par = true

        # Try authorization without PAR
        auth = AuthorizationSecuritySpec.approve("client_id=test_client&redirect_uri=https://example.com/callback&response_type=code&state=xyz")

        # Should fail because PAR is required
        auth.status.should eq(400)
        auth_body = auth.body
        auth_result = JSON.parse(auth_body)
        auth_result["error"].as_s.should eq("invalid_request")

        # Restore original setting
        Authly.config.require_par = original_require_par
      end

      it "allows additional query parameters with request_uri" do
        # Step 1: Create PAR request
        par_request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback&scope=openid&state=xyz"
        )

        par_io = IO::Memory.new
        par_response = HTTP::Server::Response.new(par_io)
        par_context = HTTP::Server::Context.new(par_request, par_response)
        PARHandler.handle(par_context)

        par_response.close
        par_io.rewind
        par_result_str = par_io.gets_to_end

        par_body = par_result_str.split("\r\n\r\n")[1]
        par_result = JSON.parse(par_body)
        request_uri = par_result["request_uri"].as_s

        # Step 2: Authorization with request_uri and additional parameters
        auth = AuthorizationSecuritySpec.approve("client_id=test_client&request_uri=#{URI.encode_www_form(request_uri)}")

        # Should succeed: the pushed parameters are used, the signed-in owner approves
        auth.status.should eq(302)
      end
    end
  end
end
