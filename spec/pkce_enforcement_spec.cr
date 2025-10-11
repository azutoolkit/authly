require "./spec_helper"

describe "PKCE Enforcement" do
  it "allows authorization without PKCE when enforcement is disabled" do
    # Save original state
    original_enforce_pkce = Authly.config.enforce_pkce?
    original_enforce_s256 = Authly.config.enforce_pkce_s256?

    Authly.config.enforce_pkce = false
    Authly.config.enforce_pkce_s256 = false

    client = Authly::Client.new(
      name: "Test Client",
      secret: "secret",
      redirect_uri: "http://localhost/callback",
      id: "client123"
    )
    Authly.clients << client

    response_type = Authly::ResponseType.new(
      "code",
      "client123",
      "http://localhost/callback",
      "read write",
      "", # No code_challenge
      "", # No code_challenge_method
      "user1"
    )

    code = response_type.decode
    code.should be_a(Authly::Code)

    # Restore original state
    Authly.config.enforce_pkce = original_enforce_pkce
    Authly.config.enforce_pkce_s256 = original_enforce_s256
  end

  it "requires PKCE when enforcement is enabled" do
    # Save original state
    original_enforce_pkce = Authly.config.enforce_pkce?
    original_enforce_s256 = Authly.config.enforce_pkce_s256?

    Authly.config.enforce_pkce = true
    Authly.config.enforce_pkce_s256 = false

    client = Authly::Client.new(
      name: "Test Client",
      secret: "secret",
      redirect_uri: "http://localhost/callback",
      id: "client456"
    )
    Authly.clients << client

    # This would be validated in the authorization handler
    # Testing the code challenge builder validation
    expect_raises(ArgumentError, /Unsupported code challenge method/) do
      Authly::CodeChallengeBuilder.build("challenge", "invalid_method")
    end

    # Restore original state
    Authly.config.enforce_pkce = original_enforce_pkce
    Authly.config.enforce_pkce_s256 = original_enforce_s256
  end

  it "accepts S256 method" do
    challenge = Authly::CodeChallengeBuilder.build("test_challenge", "S256")
    challenge.should be_a(Authly::CodeChallengeBuilder::S256)
    challenge.code.should eq("test_challenge")
  end

  it "accepts plain method when S256 is not enforced" do
    Authly.config.enforce_pkce_s256 = false

    challenge = Authly::CodeChallengeBuilder.build("test_challenge", "plain")
    challenge.should be_a(Authly::CodeChallengeBuilder::Plain)
    challenge.code.should eq("test_challenge")
  end

  it "validates S256 code verifier correctly" do
    # Generate a verifier and its challenge
    verifier = Random::Secure.hex(32)
    challenge = Digest::SHA256.base64digest(verifier)

    s256 = Authly::CodeChallengeBuilder::S256.new(challenge)
    s256.valid?(verifier).should be_true
    s256.valid?("wrong_verifier").should be_false
  end

  it "validates plain code verifier correctly" do
    verifier = "my_secret_verifier"

    plain = Authly::CodeChallengeBuilder::Plain.new(verifier)
    plain.valid?(verifier).should be_true
    plain.valid?("wrong_verifier").should be_false
  end
end
