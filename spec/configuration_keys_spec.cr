require "./spec_helper"

module Authly
  describe Configuration do
    describe "signing and verification keys" do
      it "verifies with the signing key unless told otherwise, so a default setup round-trips" do
        config = Configuration.new

        config.public_key.should eq config.secret_key
      end

      it "follows the signing key when that is set later" do
        config = Configuration.new
        config.secret_key = "a-key-set-after-construction"

        config.public_key.should eq "a-key-set-after-construction"
      end

      it "uses an explicit verification key" do
        config = Configuration.new
        config.public_key = "public-half"

        config.public_key.should eq "public-half"
        config.secret_key.should_not eq "public-half"
      end
    end
  end
end
