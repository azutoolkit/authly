require "../spec_helper"

module Authly
  describe PARHandler do
    describe "POST /oauth/par" do
      before_each do
        # Ensure test client exists (may have been removed by other tests)
        unless Authly.clients.any? { |c| c.id == "test_client" }
          Authly.clients << Authly::Client.new("test_client", "test_secret", "https://example.com/callback", "test_client", "read write admin openid profile email", "authorization_code client_credentials password refresh_token implicit")
        end
      end

      it "successfully creates a pushed authorization request" do
        request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback&scope=openid&state=xyz"
        )

        io = IO::Memory.new
        response = HTTP::Server::Response.new(io)
        context = HTTP::Server::Context.new(request, response)

        PARHandler.handle(context)

        response.close
        io.rewind
        result_str = io.gets_to_end

        response.status_code.should eq(201)

        body = result_str.split("\r\n\r\n")[1]
        result = JSON.parse(body)

        result["request_uri"].as_s.should start_with("urn:ietf:params:oauth:request_uri:")
        result["expires_in"].as_i.should eq(90)
      end

      it "authenticates client using Basic authentication" do
        credentials = Base64.strict_encode("test_client:test_secret")
        request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{
            "Authorization" => "Basic #{credentials}",
            "Content-Type"  => "application/x-www-form-urlencoded",
          },
          body: "response_type=code&redirect_uri=https://example.com/callback"
        )

        io = IO::Memory.new
        response = HTTP::Server::Response.new(io)
        context = HTTP::Server::Context.new(request, response)

        PARHandler.handle(context)

        response.close
        io.rewind

        response.status_code.should eq(201)
      end

      it "authenticates client using POST body credentials" do
        request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback"
        )

        io = IO::Memory.new
        response = HTTP::Server::Response.new(io)
        context = HTTP::Server::Context.new(request, response)

        PARHandler.handle(context)

        response.close
        io.rewind

        response.status_code.should eq(201)
      end

      it "rejects request without client authentication" do
        request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&redirect_uri=https://example.com/callback"
        )

        io = IO::Memory.new
        response = HTTP::Server::Response.new(io)
        context = HTTP::Server::Context.new(request, response)

        PARHandler.handle(context)

        response.close
        io.rewind
        result_str = io.gets_to_end

        response.status_code.should eq(400)
        body = result_str.split("\r\n\r\n")[1]
        result = JSON.parse(body)
        result["error"].as_s.should eq("invalid_client")
      end

      it "rejects request with invalid client credentials" do
        request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=invalid_client&client_secret=wrong_secret&redirect_uri=https://example.com/callback"
        )

        io = IO::Memory.new
        response = HTTP::Server::Response.new(io)
        context = HTTP::Server::Context.new(request, response)

        PARHandler.handle(context)

        response.close
        io.rewind
        result_str = io.gets_to_end

        response.status_code.should eq(401)
        body = result_str.split("\r\n\r\n")[1]
        result = JSON.parse(body)
        result["error"].as_s.should eq("invalid_client")
      end

      it "requires response_type parameter" do
        request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback"
        )

        io = IO::Memory.new
        response = HTTP::Server::Response.new(io)
        context = HTTP::Server::Context.new(request, response)

        PARHandler.handle(context)

        response.close
        io.rewind
        result_str = io.gets_to_end

        response.status_code.should eq(400)
        body = result_str.split("\r\n\r\n")[1]
        result = JSON.parse(body)
        result["error"].as_s.should eq("invalid_request")
        result["error_description"].as_s.should contain("response_type")
      end

      it "requires redirect_uri parameter" do
        request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=test_client&client_secret=test_secret"
        )

        io = IO::Memory.new
        response = HTTP::Server::Response.new(io)
        context = HTTP::Server::Context.new(request, response)

        PARHandler.handle(context)

        response.close
        io.rewind
        result_str = io.gets_to_end

        response.status_code.should eq(400)
        body = result_str.split("\r\n\r\n")[1]
        result = JSON.parse(body)
        result["error"].as_s.should eq("invalid_request")
        result["error_description"].as_s.should contain("redirect_uri")
      end

      it "validates redirect_uri" do
        request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=test_client&client_secret=test_secret&redirect_uri=invalid_uri"
        )

        io = IO::Memory.new
        response = HTTP::Server::Response.new(io)
        context = HTTP::Server::Context.new(request, response)

        PARHandler.handle(context)

        response.close
        io.rewind
        result_str = io.gets_to_end

        response.status_code.should eq(400)
        body = result_str.split("\r\n\r\n")[1]
        result = JSON.parse(body)
        result["error"].as_s.should eq("invalid_request")
      end

      it "validates response_type is supported" do
        request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=unsupported&client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback"
        )

        io = IO::Memory.new
        response = HTTP::Server::Response.new(io)
        context = HTTP::Server::Context.new(request, response)

        PARHandler.handle(context)

        response.close
        io.rewind
        result_str = io.gets_to_end

        response.status_code.should eq(400)
        body = result_str.split("\r\n\r\n")[1]
        result = JSON.parse(body)
        result["error"].as_s.should eq("invalid_request")
      end

      it "stores PKCE parameters" do
        request = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback&code_challenge=challenge123&code_challenge_method=S256"
        )

        io = IO::Memory.new
        response = HTTP::Server::Response.new(io)
        context = HTTP::Server::Context.new(request, response)

        PARHandler.handle(context)

        response.close
        io.rewind
        result_str = io.gets_to_end

        response.status_code.should eq(201)
        body = result_str.split("\r\n\r\n")[1]
        result = JSON.parse(body)
        request_uri = result["request_uri"].as_s

        # Verify parameters are stored
        par_data = Authly.config.par_store.fetch(request_uri)
        par_data.should_not be_nil
        par_data.not_nil!.params["code_challenge"].should eq("challenge123")
        par_data.not_nil!.params["code_challenge_method"].should eq("S256")
      end

      it "generates unique request_uri for each request" do
        io1 = IO::Memory.new
        request1 = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback"
        )

        response1 = HTTP::Server::Response.new(io1)
        context1 = HTTP::Server::Context.new(request1, response1)
        PARHandler.handle(context1)

        response1.close
        io1.rewind
        result_str1 = io1.gets_to_end

        body1 = result_str1.split("\r\n\r\n")[1]
        result1 = JSON.parse(body1)
        request_uri1 = result1["request_uri"].as_s

        io2 = IO::Memory.new
        request2 = HTTP::Request.new(
          "POST",
          "/oauth/par",
          headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"},
          body: "response_type=code&client_id=test_client&client_secret=test_secret&redirect_uri=https://example.com/callback"
        )

        response2 = HTTP::Server::Response.new(io2)
        context2 = HTTP::Server::Context.new(request2, response2)
        PARHandler.handle(context2)

        response2.close
        io2.rewind
        result_str2 = io2.gets_to_end

        body2 = result_str2.split("\r\n\r\n")[1]
        result2 = JSON.parse(body2)
        request_uri2 = result2["request_uri"].as_s

        request_uri1.should_not eq(request_uri2)
      end
    end
  end
end
