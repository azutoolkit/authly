require "./spec_helper"

describe "JARM (JWT Secured Authorization Response Mode)" do
  describe "JarmBuilder" do
    it "builds a JWT response with authorization code" do
      builder = Authly::JarmBuilder.new(
        issuer: "https://auth.example.com",
        audience: "client_123",
        lifetime: 10.minutes,
        signing_key: "test_secret_key_for_testing",
        signing_algorithm: JWT::Algorithm::HS256
      )

      jwt = builder.build_authorization_response(
        code: "auth_code_123",
        state: "state_xyz"
      )

      jwt.should_not be_nil
      jwt.should be_a(String)

      # Decode and verify the JWT
      payload, header = JWT.decode(jwt, "test_secret_key_for_testing", JWT::Algorithm::HS256)
      payload["iss"].as_s.should eq("https://auth.example.com")
      payload["aud"].as_s.should eq("client_123")
      payload["code"].as_s.should eq("auth_code_123")
      payload["state"].as_s.should eq("state_xyz")
      payload["exp"].as_i64.should be > 0
      payload["iat"].as_i64.should be > 0
    end

    it "builds a JWT response with access token" do
      builder = Authly::JarmBuilder.new(
        issuer: "https://auth.example.com",
        audience: "client_123",
        lifetime: 10.minutes,
        signing_key: "test_secret_key_for_testing",
        signing_algorithm: JWT::Algorithm::HS256
      )

      jwt = builder.build_authorization_response(
        access_token: "access_token_abc",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid profile",
        state: "state_xyz"
      )

      # Decode and verify the JWT
      payload, header = JWT.decode(jwt, "test_secret_key_for_testing", JWT::Algorithm::HS256)
      payload["access_token"].as_s.should eq("access_token_abc")
      payload["token_type"].as_s.should eq("Bearer")
      payload["expires_in"].as_s.should eq("3600")
      payload["scope"].as_s.should eq("openid profile")
      payload["state"].as_s.should eq("state_xyz")
    end

    it "builds a JWT response with error" do
      builder = Authly::JarmBuilder.new(
        issuer: "https://auth.example.com",
        audience: "client_123",
        lifetime: 10.minutes,
        signing_key: "test_secret_key_for_testing",
        signing_algorithm: JWT::Algorithm::HS256
      )

      jwt = builder.build_authorization_response(
        error: "access_denied",
        error_description: "User denied the request",
        state: "state_xyz"
      )

      # Decode and verify the JWT
      payload, header = JWT.decode(jwt, "test_secret_key_for_testing", JWT::Algorithm::HS256)
      payload["error"].as_s.should eq("access_denied")
      payload["error_description"].as_s.should eq("User denied the request")
      payload["state"].as_s.should eq("state_xyz")
    end

    it "generates form_post HTML" do
      html = Authly::JarmBuilder.build_form_post_html(
        "https://client.example.com/callback",
        "jwt_token_here"
      )

      html.should contain("form")
      html.should contain("https://client.example.com/callback")
      html.should contain("jwt_token_here")
      html.should contain("response")
      html.should contain("onload")
    end

    it "escapes HTML in form_post" do
      html = Authly::JarmBuilder.build_form_post_html(
        "https://client.example.com/callback?foo=<script>",
        "token_with_\"quotes\""
      )

      html.should_not contain("<script>")
      html.should contain("&lt;script&gt;")
      html.should_not contain("\"quotes\"")
    end
  end

  describe "Client JARM Configuration" do
    it "adds JARM fields to Client struct" do
      client = Authly::Client.new(
        name: "Test Client",
        secret: "secret",
        redirect_uri: "https://example.com/callback",
        id: "client_123",
        jarm_signing_alg: "RS256",
        jarm_encryption_alg: "RSA-OAEP",
        jarm_encryption_enc: "A256GCM"
      )

      client.jarm_signing_alg.should eq("RS256")
      client.jarm_encryption_alg.should eq("RSA-OAEP")
      client.jarm_encryption_enc.should eq("A256GCM")
    end

    it "implements JARM methods in Clients" do
      clients = Authly::Clients.new
      client = Authly::Client.new(
        name: "Test Client",
        secret: "secret",
        redirect_uri: "https://example.com/callback",
        id: "client_123",
        jarm_signing_alg: "RS256"
      )
      clients << client

      clients.jarm_required?("client_123").should be_true
      clients.jarm_signing_algorithm("client_123").should eq("RS256")
    end

    it "returns false for JARM required when not configured" do
      clients = Authly::Clients.new
      client = Authly::Client.new(
        name: "Test Client",
        secret: "secret",
        redirect_uri: "https://example.com/callback",
        id: "client_456"
      )
      clients << client

      clients.jarm_required?("client_456").should be_false
      clients.jarm_signing_algorithm("client_456").should be_nil
    end
  end

  describe "DynamicClient JARM Support" do
    it "accepts JARM metadata in registration request" do
      params = {
        "redirect_uris"                        => JSON::Any.new([JSON::Any.new("https://example.com/callback")]),
        "client_name"                          => JSON::Any.new("Test Client"),
        "authorization_signed_response_alg"    => JSON::Any.new("RS256"),
        "authorization_encrypted_response_alg" => JSON::Any.new("RSA-OAEP"),
        "authorization_encrypted_response_enc" => JSON::Any.new("A256GCM"),
      }

      client = Authly::DynamicClient.from_registration_request(params)
      client.authorization_signed_response_alg.should eq("RS256")
      client.authorization_encrypted_response_alg.should eq("RSA-OAEP")
      client.authorization_encrypted_response_enc.should eq("A256GCM")
    end

    it "validates JARM signing algorithm" do
      params = {
        "redirect_uris"                     => JSON::Any.new([JSON::Any.new("https://example.com/callback")]),
        "authorization_signed_response_alg" => JSON::Any.new("INVALID_ALG"),
      }

      client = Authly::DynamicClient.from_registration_request(params)
      client.valid?.should be_false
    end

    it "validates that encryption encoding is required with encryption algorithm" do
      params = {
        "redirect_uris"                        => JSON::Any.new([JSON::Any.new("https://example.com/callback")]),
        "authorization_encrypted_response_alg" => JSON::Any.new("RSA-OAEP"),
      }

      client = Authly::DynamicClient.from_registration_request(params)
      client.valid?.should be_false
    end

    it "validates JARM encryption algorithm" do
      params = {
        "redirect_uris"                        => JSON::Any.new([JSON::Any.new("https://example.com/callback")]),
        "authorization_encrypted_response_alg" => JSON::Any.new("INVALID_ALG"),
        "authorization_encrypted_response_enc" => JSON::Any.new("A256GCM"),
      }

      client = Authly::DynamicClient.from_registration_request(params)
      client.valid?.should be_false
    end

    it "validates complete JARM configuration" do
      params = {
        "redirect_uris"                        => JSON::Any.new([JSON::Any.new("https://example.com/callback")]),
        "authorization_signed_response_alg"    => JSON::Any.new("ES256"),
        "authorization_encrypted_response_alg" => JSON::Any.new("ECDH-ES"),
        "authorization_encrypted_response_enc" => JSON::Any.new("A128GCM"),
      }

      client = Authly::DynamicClient.from_registration_request(params)
      client.valid?.should be_true
    end
  end

  describe "Configuration" do
    it "adds JARM configuration options" do
      config = Authly::Configuration.new
      config.jarm_signing_key = "signing_key"
      config.jarm_signing_alg = JWT::Algorithm::ES256
      config.jarm_encryption_key = "encryption_key"
      config.jarm_encryption_alg = "RSA-OAEP"
      config.jarm_encryption_enc = "A256GCM"
      config.default_jarm_response_mode = "query.jwt"
      config.jarm_lifetime = 5.minutes

      config.jarm_signing_key.should eq("signing_key")
      config.jarm_signing_alg.should eq(JWT::Algorithm::ES256)
      config.jarm_encryption_key.should eq("encryption_key")
      config.jarm_encryption_alg.should eq("RSA-OAEP")
      config.jarm_encryption_enc.should eq("A256GCM")
      config.default_jarm_response_mode.should eq("query.jwt")
      config.jarm_lifetime.should eq(5.minutes)
    end
  end
end
