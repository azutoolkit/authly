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

    describe "S256 Code Challenge (RFC 7636 appendix B)" do
      verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
      rfc_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

      it "accepts the unpadded base64url challenge a standards-compliant client sends" do
        CodeChallengeBuilder.build(rfc_challenge, "S256").valid?(verifier).should be_true
      end

      it "still accepts the padded standard base64 challenge older clients of this library sent" do
        CodeChallengeBuilder.build(Digest::SHA256.base64digest(verifier), "S256").valid?(verifier).should be_true
      end

      it "rejects another verifier" do
        CodeChallengeBuilder.build(rfc_challenge, "S256").valid?("another-verifier").should be_false
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
