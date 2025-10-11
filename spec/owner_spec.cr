require "./spec_helper"

module Authly
  describe Owner do
    it "initializes with username and password" do
      owner = Owner.new("john_doe", "password123")

      owner.username.should eq "john_doe"
      owner.password.should eq "password123"
    end

    it "generates unique id for each owner" do
      owner1 = Owner.new("john", "pass1")
      owner2 = Owner.new("jane", "pass2")

      owner1.id.should_not eq owner2.id
      owner1.id.should_not be_empty
      owner2.id.should_not be_empty
    end

    it "allows updating username" do
      owner = Owner.new("john", "pass")
      owner.username = "john_updated"

      owner.username.should eq "john_updated"
    end

    it "allows updating password" do
      owner = Owner.new("john", "pass")
      owner.password = "new_pass"

      owner.password.should eq "new_pass"
    end
  end

  describe Owners do
    describe "#<<" do
      it "adds an owner to the collection" do
        owners = Owners.new
        owner = Owner.new("john", "pass123")

        owners << owner
        owners.any? { |o| o.username == "john" }.should be_true
      end
    end

    describe "#authorized?" do
      it "returns true with valid username and password" do
        owners = Owners.new
        owners << Owner.new("john", "secret123")

        owners.authorized?("john", "secret123").should be_true
      end

      it "returns false with invalid password" do
        owners = Owners.new
        owners << Owner.new("john", "secret123")

        owners.authorized?("john", "wrong_password").should be_false
      end

      it "returns false with invalid username" do
        owners = Owners.new
        owners << Owner.new("john", "secret123")

        owners.authorized?("jane", "secret123").should be_false
      end

      it "returns false when no owners exist" do
        owners = Owners.new

        owners.authorized?("john", "password").should be_false
      end

      it "distinguishes between different owners" do
        owners = Owners.new
        owners << Owner.new("john", "pass1")
        owners << Owner.new("jane", "pass2")

        owners.authorized?("john", "pass1").should be_true
        owners.authorized?("jane", "pass2").should be_true
        owners.authorized?("john", "pass2").should be_false
      end
    end

    describe "#id_token" do
      it "generates ID token with user claims" do
        owners = Owners.new
        owner = Owner.new("john_doe", "password")
        owners << owner

        id_token = owners.id_token("john_doe")

        id_token["user_id"].should eq "john_doe"
        id_token["sub"].should eq owner.id
        id_token["iss"].should eq Authly.config.issuer
      end

      it "includes issued at timestamp" do
        owners = Owners.new
        owners << Owner.new("john", "password")

        id_token = owners.id_token("john")

        id_token["iat"].should be_a(Int64)
        id_token["iat"].as(Int64).should be_close(Time.utc.to_unix, 2)
      end

      it "includes expiration timestamp" do
        owners = Owners.new
        owners << Owner.new("john", "password")

        id_token = owners.id_token("john")
        expected_exp = Authly.config.access_ttl.from_now.to_unix

        id_token["exp"].should be_a(Int64)
        id_token["exp"].as(Int64).should be_close(expected_exp, 2)
      end

      it "raises error for non-existent user" do
        owners = Owners.new
        owners << Owner.new("john", "password")

        expect_raises(Exception) do
          owners.id_token("non_existent_user")
        end
      end

      it "uses owner's unique id as sub claim" do
        owners = Owners.new
        owner1 = Owner.new("john", "pass1")
        owner2 = Owner.new("jane", "pass2")
        owners << owner1
        owners << owner2

        token1 = owners.id_token("john")
        token2 = owners.id_token("jane")

        token1["sub"].should eq owner1.id
        token2["sub"].should eq owner2.id
        token1["sub"].should_not eq token2["sub"]
      end
    end

    describe "#each" do
      it "iterates over all owners" do
        owners = Owners.new
        owners << Owner.new("john", "pass1")
        owners << Owner.new("jane", "pass2")

        count = 0
        owners.each { count += 1 }
        count.should eq 2
      end

      it "yields each owner" do
        owners = Owners.new
        owners << Owner.new("john", "pass1")
        owners << Owner.new("jane", "pass2")

        usernames = [] of String
        owners.each { |o| usernames << o.username }
        usernames.should eq ["john", "jane"]
      end
    end
  end
end
