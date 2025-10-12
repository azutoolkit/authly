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

        # Pre-store the state (simulating the consent page flow)
        Authly.config.state_store.store("abc123")

        # Step 2: User authorization with request_uri
        auth_request = HTTP::Request.new(
          "GET",
          "/oauth/authorize?client_id=test_client&request_uri=#{URI.encode_www_form(request_uri)}&user_id=user123&consent=approved"
        )

        auth_io = IO::Memory.new
        auth_response = HTTP::Server::Response.new(auth_io)
        auth_context = HTTP::Server::Context.new(auth_request, auth_response)
        AuthorizationHandler.handle(auth_context)

        auth_response.close
        auth_io.rewind

        # Should redirect with authorization code
        auth_response.status_code.should eq(302)
        location = auth_response.headers["Location"]
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

        # Pre-store the state
        Authly.config.state_store.store("xyz")

        # Step 2: First authorization attempt (should succeed)
        auth_request1 = HTTP::Request.new(
          "GET",
          "/oauth/authorize?client_id=test_client&request_uri=#{URI.encode_www_form(request_uri)}&user_id=user123&consent=approved"
        )

        auth_io1 = IO::Memory.new
        auth_response1 = HTTP::Server::Response.new(auth_io1)
        auth_context1 = HTTP::Server::Context.new(auth_request1, auth_response1)
        AuthorizationHandler.handle(auth_context1)

        auth_response1.close
        auth_io1.rewind

        auth_response1.status_code.should eq(302)

        # Step 3: Second authorization attempt with same request_uri (should fail)
        auth_request2 = HTTP::Request.new(
          "GET",
          "/oauth/authorize?client_id=test_client&request_uri=#{URI.encode_www_form(request_uri)}&user_id=user123&consent=approved"
        )

        auth_io2 = IO::Memory.new
        auth_response2 = HTTP::Server::Response.new(auth_io2)
        auth_context2 = HTTP::Server::Context.new(auth_request2, auth_response2)
        AuthorizationHandler.handle(auth_context2)

        auth_response2.close
        auth_io2.rewind

        auth_response2.status_code.should eq(400)
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
        auth_request = HTTP::Request.new(
          "GET",
          "/oauth/authorize?client_id=different_client&request_uri=#{URI.encode_www_form(request_uri)}&user_id=user123&consent=approved"
        )

        auth_io = IO::Memory.new
        auth_response = HTTP::Server::Response.new(auth_io)
        auth_context = HTTP::Server::Context.new(auth_request, auth_response)
        AuthorizationHandler.handle(auth_context)

        auth_response.close
        auth_io.rewind

        # Should fail due to client_id mismatch
        auth_response.status_code.should eq(400)
      end

      it "handles expired request_uri" do
        # Create PAR store with short TTL for testing
        original_store = Authly.config.par_store
        test_store = InMemoryPARStore.new(0.seconds)
        Authly.config.par_store = test_store

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
        auth_request = HTTP::Request.new(
          "GET",
          "/oauth/authorize?client_id=test_client&request_uri=#{URI.encode_www_form(request_uri)}&user_id=user123&consent=approved"
        )

        auth_io = IO::Memory.new
        auth_response = HTTP::Server::Response.new(auth_io)
        auth_context = HTTP::Server::Context.new(auth_request, auth_response)
        AuthorizationHandler.handle(auth_context)

        auth_response.close
        auth_io.rewind

        # Should fail due to expiration
        auth_response.status_code.should eq(400)

        # Restore original store
        Authly.config.par_store = original_store
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

        # Pre-store the state
        Authly.config.state_store.store("pkce123")

        # Step 2: Authorize with request_uri
        auth_request = HTTP::Request.new(
          "GET",
          "/oauth/authorize?client_id=test_client&request_uri=#{URI.encode_www_form(request_uri)}&user_id=user123&consent=approved"
        )

        auth_io = IO::Memory.new
        auth_response = HTTP::Server::Response.new(auth_io)
        auth_context = HTTP::Server::Context.new(auth_request, auth_response)
        AuthorizationHandler.handle(auth_context)

        auth_response.close
        auth_io.rewind

        # Should succeed with PKCE parameters
        auth_response.status_code.should eq(302)
        location = auth_response.headers["Location"]
        location.should contain("code=")
      end

      it "enforces PAR when require_par is enabled" do
        # Enable PAR requirement
        original_require_par = Authly.config.require_par?
        Authly.config.require_par = true

        # Try authorization without PAR
        auth_request = HTTP::Request.new(
          "GET",
          "/oauth/authorize?client_id=test_client&redirect_uri=https://example.com/callback&response_type=code&user_id=user123&consent=approved&state=xyz"
        )

        auth_io = IO::Memory.new
        auth_response = HTTP::Server::Response.new(auth_io)
        auth_context = HTTP::Server::Context.new(auth_request, auth_response)
        AuthorizationHandler.handle(auth_context)

        auth_response.close
        auth_io.rewind
        auth_result_str = auth_io.gets_to_end

        # Should fail because PAR is required
        auth_response.status_code.should eq(400)
        auth_body = auth_result_str.split("\r\n\r\n")[1]
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

        # Pre-store the state
        Authly.config.state_store.store("xyz")

        # Step 2: Authorization with request_uri and additional parameters
        auth_request = HTTP::Request.new(
          "GET",
          "/oauth/authorize?client_id=test_client&request_uri=#{URI.encode_www_form(request_uri)}&user_id=user123&consent=approved"
        )

        auth_io = IO::Memory.new
        auth_response = HTTP::Server::Response.new(auth_io)
        auth_context = HTTP::Server::Context.new(auth_request, auth_response)
        AuthorizationHandler.handle(auth_context)

        auth_response.close
        auth_io.rewind

        # Should succeed - user_id and consent from query params
        auth_response.status_code.should eq(302)
      end
    end
  end
end
