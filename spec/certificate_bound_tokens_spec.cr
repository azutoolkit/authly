require "./spec_helper"
require "base64"

describe "Certificate-Bound Access Tokens" do
  describe Authly::CertificateValidator do
    it "calculates SHA-256 thumbprint of certificate" do
      cert_data = "sample_certificate_data"
      thumbprint = Authly::CertificateValidator.calculate_thumbprint(cert_data)

      thumbprint.should_not be_empty
      # Thumbprint should be base64url encoded (no padding)
      thumbprint.should_not contain("=")
    end

    it "returns consistent thumbprints for same certificate" do
      cert_data = "sample_certificate_data"
      thumbprint1 = Authly::CertificateValidator.calculate_thumbprint(cert_data)
      thumbprint2 = Authly::CertificateValidator.calculate_thumbprint(cert_data)

      thumbprint1.should eq(thumbprint2)
    end

    it "returns different thumbprints for different certificates" do
      cert1 = "certificate_data_1"
      cert2 = "certificate_data_2"

      thumbprint1 = Authly::CertificateValidator.calculate_thumbprint(cert1)
      thumbprint2 = Authly::CertificateValidator.calculate_thumbprint(cert2)

      thumbprint1.should_not eq(thumbprint2)
    end

    it "extracts certificate from X-Client-Certificate header" do
      cert_data = "sample_certificate"
      encoded_cert = Base64.strict_encode(cert_data)

      io = IO::Memory.new
      response = HTTP::Server::Response.new(io)
      headers = HTTP::Headers.new
      headers["X-Client-Certificate"] = encoded_cert
      request = HTTP::Request.new("GET", "/test", headers)
      context = HTTP::Server::Context.new(request, response)

      certificate = Authly::CertificateValidator.extract_certificate(context)
      certificate.should eq(cert_data)
    end

    it "returns nil when no certificate header present" do
      io = IO::Memory.new
      response = HTTP::Server::Response.new(io)
      request = HTTP::Request.new("GET", "/test")
      context = HTTP::Server::Context.new(request, response)

      certificate = Authly::CertificateValidator.extract_certificate(context)
      certificate.should be_nil
    end

    it "validates certificate when no CAs configured" do
      cert_data = "sample_certificate"
      result = Authly::CertificateValidator.valid_certificate?(cert_data, [] of String)

      result.should be_true
    end

    it "validates non-empty certificate" do
      cert_data = "sample_certificate"
      cas = ["ca1", "ca2"]
      result = Authly::CertificateValidator.valid_certificate?(cert_data, cas)

      result.should be_true
    end
  end

  describe Authly::TokenBinder do
    it "extracts thumbprint from token data" do
      token_data = {
        "sub" => JSON::Any.new("user123"),
        "cnf" => JSON::Any.new({
          "x5t#S256" => JSON::Any.new("abc123xyz"),
        }),
      }

      thumbprint = Authly::TokenBinder.extract_thumbprint(token_data)
      thumbprint.should eq("abc123xyz")
    end

    it "returns nil when no cnf claim present" do
      token_data = {
        "sub" => JSON::Any.new("user123"),
      }

      thumbprint = Authly::TokenBinder.extract_thumbprint(token_data)
      thumbprint.should be_nil
    end

    it "returns nil when cnf claim has no x5t#S256" do
      token_data = {
        "sub" => JSON::Any.new("user123"),
        "cnf" => JSON::Any.new({
          "other_field" => JSON::Any.new("value"),
        }),
      }

      thumbprint = Authly::TokenBinder.extract_thumbprint(token_data)
      thumbprint.should be_nil
    end
  end

  describe "Token generation with certificate binding" do
    it "includes cnf claim in JWT when thumbprint provided" do
      Authly.config.token_strategy = :jwt
      Authly.config.require_certificate_bound_tokens = true

      client_id = "test_client"
      scope = "read write"
      cert_thumbprint = "test_thumbprint_123"

      token = Authly::AccessToken.new(client_id, scope, nil, cert_thumbprint)

      # Decode the JWT to verify cnf claim
      payload, _ = Authly.jwt_decode(token.access_token)

      payload["cnf"]?.should_not be_nil
      cnf = payload["cnf"].as_h
      cnf["x5t#S256"].as_s.should eq(cert_thumbprint)

      # Reset config
      Authly.config.require_certificate_bound_tokens = false
    end

    it "generates token without cnf when no thumbprint provided" do
      Authly.config.token_strategy = :jwt
      Authly.config.require_certificate_bound_tokens = false

      client_id = "test_client"
      scope = "read write"

      token = Authly::AccessToken.new(client_id, scope)

      # Decode the JWT
      payload, _ = Authly.jwt_decode(token.access_token)

      payload["cnf"]?.should be_nil
    end

    it "stores certificate thumbprint for opaque tokens" do
      Authly.config.token_strategy = :opaque
      Authly.config.require_certificate_bound_tokens = true

      client_id = "test_client"
      scope = "read write"
      cert_thumbprint = "test_thumbprint_456"

      token = Authly::AccessToken.new(client_id, scope, nil, cert_thumbprint)

      # Fetch token metadata from store
      token_meta = Authly.config.token_store.fetch(token.access_token)

      token_meta.should_not be_nil
      token_meta.not_nil!["cnf"]?.should eq(cert_thumbprint)

      # Reset config
      Authly.config.token_strategy = :jwt
      Authly.config.require_certificate_bound_tokens = false
    end
  end
end
