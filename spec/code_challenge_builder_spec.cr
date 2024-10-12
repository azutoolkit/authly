require "./spec_helper"

module Authly
  describe CodeChallengeBuilder do
    code = Random::Secure.hex(32)
    code_verifier = Base64.urlsafe_encode(code).gsub(/{\+|\=|\/}/, "")
    code_challenge = Digest::SHA256.base64digest(code_verifier)

    describe "Plain Code Challenge" do
      code_challenge_method = "plain"
      challenge = CodeChallengeBuilder.build(code_challenge, code_challenge_method)

      it "is a valid code challenge" do
        challenge.should be_a CodeChallengeBuilder::Plain
        challenge.valid?(code_challenge).should be_true
      end
    end

    describe "S256 Code Challenge" do
      code_challenge_method = "S256"
      challenge = CodeChallengeBuilder.build(code_challenge, code_challenge_method)

      it "is a valid code challenge" do
        challenge.should be_a CodeChallengeBuilder::S256
        challenge.valid?(code_verifier).should be_true
      end
    end

    describe "S256 Code Challenge" do
      challenge = CodeChallengeBuilder.build

      it "is a valid code challenge" do
        challenge.should be_a CodeChallengeBuilder::S256
        challenge.valid?("").should be_false
      end
    end
  end
end
