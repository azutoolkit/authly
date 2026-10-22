require "./spec_helper"

module Authly
  describe Error do
    describe "error creation" do
      it "creates invalid_token error with correct message and code" do
        expect_raises(Error(400), "The token is invalid or expired") do
          Error.invalid_token
        end
      end

      it "creates unsupported_token_type error" do
        expect_raises(Error(400), "The authorization server does not support the presented token type") do
          Error.unsupported_token_type
        end
      end

      it "creates owner_credentials error" do
        expect_raises(Error(400), "Invalid owner credentials") do
          Error.owner_credentials
        end
      end

      it "creates unsupported_grant_type error" do
        expect_raises(Error(400), "Invalid or unknown grant type") do
          Error.unsupported_grant_type
        end
      end

      it "creates unauthorized_client error with 401 code" do
        expect_raises(Error(401), "This client is not authorized to use the requested grant type") do
          Error.unauthorized_client
        end
      end

      it "creates invalid_redirect_uri error" do
        expect_raises(Error(400), "Invalid redirect uri") do
          Error.invalid_redirect_uri
        end
      end

      it "creates invalid_state error" do
        expect_raises(Error(400), "Invalid state") do
          Error.invalid_state
        end
      end

      it "creates invalid_grant error" do
        expect_raises(Error(400), "The authorization code is invalid or expired.") do
          Error.invalid_grant
        end
      end

      it "creates invalid_scope error" do
        expect_raises(Error(400), "Invalid scope value in the request") do
          Error.invalid_scope
        end
      end

      it "creates invalid_response_type error" do
        expect_raises(Error(400), "The response type is invalid.") do
          Error.invalid_response_type
        end
      end

      it "creates authorization_pending error" do
        expect_raises(Error(400), "The authorization request is still pending; the client should retry the request") do
          Error.authorization_pending
        end
      end

      it "creates slow_down error" do
        expect_raises(Error(400), "The client is polling too frequently and should slow down") do
          Error.slow_down
        end
      end

      it "creates expired_token error" do
        expect_raises(Error(400), "The device code has expired; the client should request a new device authorization") do
          Error.expired_token
        end
      end
    end

    describe "#code" do
      it "returns correct HTTP status code" do
        Error.invalid_token
      rescue e : Error(400)
        e.code.should eq 400
      end

      it "returns 401 for unauthorized_client" do
        Error.unauthorized_client
      rescue e : Error(401)
        e.code.should eq 401
      end
    end

    describe "#type" do
      it "returns error type as symbol" do
        Error.invalid_grant
      rescue e : Error
        e.type.should eq :invalid_grant
      end

      it "returns correct type for each error" do
        Error.authorization_pending
      rescue e : Error
        e.type.should eq :authorization_pending
      end
    end

    describe "#message" do
      it "returns descriptive error message" do
        Error.invalid_scope
      rescue e : Error
        e.message.should eq "Invalid scope value in the request"
      end

      it "matches ERROR_MSG hash" do
        Error.expired_token
      rescue e : Error
        e.message.should eq ERROR_MSG[:expired_token]
      end
    end

    describe ".bad_request" do
      it "creates custom error with specified type" do
        expect_raises(Error(400), "Invalid redirect uri") do
          Error.bad_request(:invalid_redirect_uri)
        end
      end

      it "uses 400 status code for bad_request" do
        Error.bad_request(:invalid_scope)
      rescue e : Error(400)
        e.code.should eq 400
      end
    end

    describe "ERROR_MSG constant" do
      it "contains all expected error messages" do
        ERROR_MSG[:invalid_redirect_uri].should eq "Invalid redirect uri"
        ERROR_MSG[:invalid_state].should eq "Invalid state"
        ERROR_MSG[:invalid_scope].should eq "Invalid scope value in the request"
        ERROR_MSG[:invalid_client].should eq "Client authentication failed, such as if the request contains an invalid client ID or secret."
        ERROR_MSG[:invalid_request].should eq "The request is missing a parameter so the server can't proceed with the request"
        ERROR_MSG[:invalid_grant].should eq "The authorization code is invalid or expired."
        ERROR_MSG[:invalid_response_type].should eq "The response type is invalid."
        ERROR_MSG[:owner_credentials].should eq "Invalid owner credentials"
        ERROR_MSG[:unauthorized_client].should eq "This client is not authorized to use the requested grant type"
        ERROR_MSG[:unsupported_grant_type].should eq "Invalid or unknown grant type"
        ERROR_MSG[:access_denied].should eq "The user or authorization server denied the request"
        ERROR_MSG[:unsupported_token_type].should eq "The authorization server does not support the presented token type"
        ERROR_MSG[:invalid_token].should eq "The token is invalid or expired"
        ERROR_MSG[:authorization_pending].should eq "The authorization request is still pending; the client should retry the request"
        ERROR_MSG[:slow_down].should eq "The client is polling too frequently and should slow down"
        ERROR_MSG[:expired_token].should eq "The device code has expired; the client should request a new device authorization"
      end
    end
  end
end
