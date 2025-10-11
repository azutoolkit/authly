require "./spec_helper"

module Authly
  describe Client do
    it "initializes with required attributes" do
      client = Client.new("TestApp", "secret123", "https://example.com/callback", "client_1")

      client.name.should eq "TestApp"
      client.secret.should eq "secret123"
      client.redirect_uri.should eq "https://example.com/callback"
      client.id.should eq "client_1"
      client.scopes.should eq "read"
    end

    it "accepts custom scopes during initialization" do
      client = Client.new("TestApp", "secret123", "https://example.com/callback", "client_1", "read write admin")

      client.scopes.should eq "read write admin"
    end
  end

  describe Clients do
    describe "#<<" do
      it "adds a client to the collection" do
        clients = Clients.new
        client = Client.new("TestApp", "secret123", "https://example.com/callback", "client_1")

        clients << client
        clients.any? { |item| item.id == "client_1" }.should be_true
      end
    end

    describe "#valid_redirect?" do
      it "returns true for valid client_id and redirect_uri combination" do
        clients = Clients.new
        clients << Client.new("App1", "secret", "https://app1.com/callback", "1")

        clients.valid_redirect?("1", "https://app1.com/callback").should be_true
      end

      it "returns false for invalid client_id" do
        clients = Clients.new
        clients << Client.new("App1", "secret", "https://app1.com/callback", "1")

        clients.valid_redirect?("999", "https://app1.com/callback").should be_false
      end

      it "returns false for invalid redirect_uri" do
        clients = Clients.new
        clients << Client.new("App1", "secret", "https://app1.com/callback", "1")

        clients.valid_redirect?("1", "https://malicious.com/callback").should be_false
      end

      it "returns false when no clients exist" do
        clients = Clients.new

        clients.valid_redirect?("1", "https://example.com").should be_false
      end
    end

    describe "#authorized?" do
      it "returns true with valid client_id and client_secret" do
        clients = Clients.new
        clients << Client.new("App1", "secret123", "https://app1.com/callback", "1")

        clients.authorized?("1", "secret123").should be_true
      end

      it "returns false with invalid client_secret" do
        clients = Clients.new
        clients << Client.new("App1", "secret123", "https://app1.com/callback", "1")

        clients.authorized?("1", "wrong_secret").should be_false
      end

      it "returns false with invalid client_id" do
        clients = Clients.new
        clients << Client.new("App1", "secret123", "https://app1.com/callback", "1")

        clients.authorized?("999", "secret123").should be_false
      end

      it "validates with redirect_uri and code" do
        clients = Clients.new
        clients << Client.new("App1", "secret123", "https://app1.com/callback", "1")

        result = clients.authorized?("1", "secret123", "https://app1.com/callback", "code_value")
        result.should be_true
      end

      it "validates with redirect_uri, code, and verifier" do
        clients = Clients.new
        clients << Client.new("App1", "secret123", "https://app1.com/callback", "1")

        result = clients.authorized?("1", "secret123", "https://app1.com/callback", "code", "verifier")
        result.should be_true
      end
    end

    describe "#allowed_scopes?" do
      it "returns true when requested scopes match client scopes" do
        clients = Clients.new
        clients << Client.new("App1", "secret", "https://app1.com/callback", "1", "read write")

        clients.allowed_scopes?("1", "read write").should be_true
      end

      it "returns true when requested scopes are subset of client scopes" do
        clients = Clients.new
        clients << Client.new("App1", "secret", "https://app1.com/callback", "1", "read write admin")

        clients.allowed_scopes?("1", "read write").should be_true
      end

      it "returns false when requested scopes exceed client scopes" do
        clients = Clients.new
        clients << Client.new("App1", "secret", "https://app1.com/callback", "1", "read")

        clients.allowed_scopes?("1", "read write admin").should be_false
      end

      it "returns false for non-existent client" do
        clients = Clients.new

        clients.allowed_scopes?("999", "read").should be_false
      end

      it "handles single scope correctly" do
        clients = Clients.new
        clients << Client.new("App1", "secret", "https://app1.com/callback", "1", "read")

        clients.allowed_scopes?("1", "read").should be_true
      end
    end

    describe "#each" do
      it "iterates over all clients" do
        clients = Clients.new
        clients << Client.new("App1", "secret1", "https://app1.com/callback", "1")
        clients << Client.new("App2", "secret2", "https://app2.com/callback", "2")

        count = 0
        clients.each { count += 1 }
        count.should eq 2
      end

      it "yields each client" do
        clients = Clients.new
        client1 = Client.new("App1", "secret1", "https://app1.com/callback", "1")
        client2 = Client.new("App2", "secret2", "https://app2.com/callback", "2")
        clients << client1
        clients << client2

        ids = [] of String
        clients.each { |client| ids << client.id }
        ids.should eq ["1", "2"]
      end
    end
  end
end
