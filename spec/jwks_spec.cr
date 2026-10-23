require "./spec_helper"
require "./support/bearer_helpers"

# The public keys were generated with `openssl`, and the expected members are what openssl reports
# for them (RSA modulus, EC point), so the builder is not checked against itself.
module JWKSSpec
  def self.pem(label : String, body : String) : String
    "-----BEGIN #{label}-----\n#{body}\n-----END #{label}-----\n"
  end

  RSA_PUBLIC = pem("PUBLIC KEY", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGI6WfAtvBj7ky20cvJu4K/UlnBUkPo9Ibm/FIRQDbgtTrABRallgQ2Ue3qJOUj6JofA1YXpP61KvVwgghnZpcOcOtC+fCJzJ9xBnz1Ag9Am4ISitKhAEshmfftGJHpZtDvBnn3rM4QjFkO3PcW6UEI1FYgg072VHL5dJ8TgG884oKlfVeQzo/Ubw8NxumIhFx2SnBWHY5oKQvp9Z5G0QlkGWPthaL34j0tqKU+JH1fldZ54cj35WU+s7dnASqUBXw2gtOJ5D1C1VVdzDwkN3mX+fOp3ObKij+q6MkD6+MDs083fghi4PNHpOjtbSuYR11dUUPtQtjWZAn59Q5P0iwIDAQAB")

  RSA_PKCS1 = pem("RSA PUBLIC KEY", "MIIBCgKCAQEAuGI6WfAtvBj7ky20cvJu4K/UlnBUkPo9Ibm/FIRQDbgtTrABRallgQ2Ue3qJOUj6JofA1YXpP61KvVwgghnZpcOcOtC+fCJzJ9xBnz1Ag9Am4ISitKhAEshmfftGJHpZtDvBnn3rM4QjFkO3PcW6UEI1FYgg072VHL5dJ8TgG884oKlfVeQzo/Ubw8NxumIhFx2SnBWHY5oKQvp9Z5G0QlkGWPthaL34j0tqKU+JH1fldZ54cj35WU+s7dnASqUBXw2gtOJ5D1C1VVdzDwkN3mX+fOp3ObKij+q6MkD6+MDs083fghi4PNHpOjtbSuYR11dUUPtQtjWZAn59Q5P0iwIDAQAB")

  RSA_MODULUS = "b8623a59f02dbc18fb932db472f26ee0afd496705490fa3d21b9bf1484500db82d4eb00145a965810d947b7a893948fa2687c0d585e93fad4abd5c208219d9a5c39c3ad0be7c227327dc419f3d4083d026e084a2b4a84012c8667dfb46247a59b43bc19e7deb3384231643b73dc5ba504235158820d3bd951cbe5d27c4e01bcf38a0a95f55e433a3f51bc3c371ba6221171d929c1587639a0a42fa7d6791b442590658fb6168bdf88f4b6a294f891f57e5759e78723df9594facedd9c04aa5015f0da0b4e2790f50b55557730f090dde65fe7cea7739b2a28feaba3240faf8c0ecd3cddf8218b83cd1e93a3b5b4ae611d7575450fb50b63599027e7d4393f48b"

  P256 = pem("PUBLIC KEY", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnkWbXLMYr+TfJ13jzYDO6Mp3V9qthfbuqTcClWWyNlyRyo5b86jLmdQ/BGt31YfOkkIMNxpDug2/Ed+rDmlk1Q==")

  P384 = pem("PUBLIC KEY", "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE/j/I2ZAD5lJCR7eIGBGganxOf8v5SE7AmYH0acUo0D0zBOb1dQxwI+iqoCyyMTVrI/GuM9rIlzPpDEP6794JrI4Fkz55JbLu9XWzB9eD+Is2c3gMebrPEzS8or84I6jV")

  P521 = pem("PUBLIC KEY", "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA6/yl7ALwM97G/YS5dhUftTlAWFQUZe9fqhuVbpZAxpozII8zPnBC12aHy8F+UnEF2INpBTmjgDIgTvWUmRWScKkAZs7e8UZTYmFQBZcFPDP9Acagfu/xF+KtwlVnOTD0QhpY6GU86ZXFYbLyC6tTY44AtOPY32G2t77NiMe8Wu2uQBg=")

  EC = {
    "ES256" => {"P-256", P256, "049e459b5cb318afe4df275de3cd80cee8ca7757daad85f6eea937029565b2365c91ca8e5bf3a8cb99d43f046b77d587ce92420c371a43ba0dbf11dfab0e6964d5"},
    "ES384" => {"P-384", P384, "04fe3fc8d99003e6524247b7881811a06a7c4e7fcbf9484ec09981f469c528d03d3304e6f5750c7023e8aaa02cb231356b23f1ae33dac89733e90c43faefde09ac8e05933e7925b2eef575b307d783f88b3673780c79bacf1334bca2bf3823a8d5"},
    "ES512" => {"P-521", P521, "0400ebfca5ec02f033dec6fd84b976151fb5394058541465ef5faa1b956e9640c69a33208f333e7042d76687cbc17e527105d883690539a38032204ef59499159270a90066cedef146536261500597053c33fd01c6a07eeff117e2adc255673930f4421a58e8653ce995c561b2f20bab53638e00b4e3d8df61b6b7becd88c7bc5aedae4018"},
  }

  def self.hex(value : String) : String
    Base64.decode(value).hexstring
  end

  def self.keys(algorithm : JWT::Algorithm, public_key : String) : Array(Hash(String, String))
    with_key(algorithm, public_key, public_key) { Authly::JWKS.new.keys }
  end

  def self.with_key(algorithm : JWT::Algorithm, secret_key : String, public_key : String, &)
    config = Authly.config
    previous = {config.algorithm, config.secret_key, config.public_key}
    config.algorithm = algorithm
    config.secret_key = secret_key
    config.public_key = public_key
    begin
      yield
    ensure
      config.algorithm, config.secret_key, config.public_key = previous
    end
  end

  def self.tlv(tag : Int, content : Bytes) : Bytes
    length = content.size < 128 ? Bytes[content.size] : Bytes[0x82, content.size >> 8, content.size & 0xff]
    Bytes[tag] + length + content
  end
end

describe Authly::JWKS do
  it "is empty for HMAC and never contains the secret" do
    json = Authly::JWKS.new.to_json

    JSON.parse(json)["keys"].as_a.should be_empty
    json.should_not contain(Authly.config.secret_key)
  end

  it "publishes an RSA public key with the modulus openssl reports" do
    [JWKSSpec::RSA_PUBLIC, JWKSSpec::RSA_PKCS1].each do |pem|
      key = JWKSSpec.keys(JWT::Algorithm::RS256, pem).first

      key["kty"].should eq "RSA"
      key["alg"].should eq "RS256"
      key["use"].should eq "sig"
      JWKSSpec.hex(key["n"]).should eq JWKSSpec::RSA_MODULUS
      key["e"].should eq "AQAB"
    end
  end

  it "names the RSA algorithm in use" do
    JWKSSpec.keys(JWT::Algorithm::RS512, JWKSSpec::RSA_PUBLIC).first["alg"].should eq "RS512"
  end

  JWKSSpec::EC.each do |algorithm, (curve, pem, point)|
    it "publishes an #{curve} public key for #{algorithm}" do
      key = JWKSSpec.keys(JWT::Algorithm.parse(algorithm), pem).first

      key["kty"].should eq "EC"
      key["crv"].should eq curve
      key["alg"].should eq algorithm
      (JWKSSpec.hex(key["x"]) + JWKSSpec.hex(key["y"])).should eq point[2..]
    end
  end

  it "uses the RFC 7638 thumbprint as kid" do
    # The example key of RFC 7638 section 3.1, wrapped into a PKCS#1 public key.
    n = Base64.decode("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw==")
    integers = JWKSSpec.tlv(0x02, Bytes[0] + n) + JWKSSpec.tlv(0x02, Bytes[1, 0, 1])
    der = JWKSSpec.tlv(0x30, integers)
    pem = "-----BEGIN RSA PUBLIC KEY-----\n#{Base64.encode(der)}-----END RSA PUBLIC KEY-----\n"

    JWKSSpec.keys(JWT::Algorithm::RS256, pem).first["kid"].should eq "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
  end

  it "refuses a private key and anything that is not a PEM public key" do
    private_pem = OpenSSL::PKey::RSA.new(2048).to_pem

    [private_pem, "not a pem", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"].each do |bad|
      expect_raises(ArgumentError) { JWKSSpec.keys(JWT::Algorithm::RS256, bad) }
    end
  end
end

describe "the well-known endpoints" do
  it "serve the key set with caching headers" do
    BearerSpec.with_server([Authly::Handler.new] of HTTP::Handler) do |client|
      JWKSSpec.with_key(JWT::Algorithm::ES256, "unused", JWKSSpec::EC["ES256"][1]) do
        response = client.get("/.well-known/jwks.json")

        response.status_code.should eq 200
        response.content_type.should eq "application/jwk-set+json"
        response.headers["Cache-Control"].should eq "public, max-age=300"
        JSON.parse(response.body)["keys"][0]["crv"].should eq "P-256"
      end
    end
  end

  it "answer 500 without key material when the configured key cannot be published" do
    BearerSpec.with_server([Authly::Handler.new] of HTTP::Handler) do |client|
      private_pem = OpenSSL::PKey::RSA.new(2048).to_pem
      JWKSSpec.with_key(JWT::Algorithm::RS256, private_pem, private_pem) do
        response = client.get("/.well-known/jwks.json")

        response.status_code.should eq 500
        response.body.should_not contain("PRIVATE")
      end
    end
  end

  it "serve the authorization server metadata next to the OpenID configuration" do
    BearerSpec.with_server([Authly::Handler.new] of HTTP::Handler) do |client|
      oauth = JSON.parse(client.get("/.well-known/oauth-authorization-server").body)
      openid = JSON.parse(client.get("/.well-known/openid-configuration").body)

      oauth.should eq openid
      oauth["jwks_uri"].as_s.should end_with "/.well-known/jwks.json"
    end
  end

  it "only answer GET" do
    BearerSpec.with_server([Authly::Handler.new] of HTTP::Handler) do |client|
      client.post("/.well-known/jwks.json").status_code.should eq 404
    end
  end
end

describe "Bearer with an asymmetric key" do
  it "verifies RS256 tokens with the public key alone" do
    rsa = OpenSSL::PKey::RSA.new(2048)
    JWKSSpec.with_key(JWT::Algorithm::RS256, rsa.to_pem, rsa.public_key.to_pem) do
      token = Authly::AccessToken.new("test_client", "read:users", subject: "carol").access_token
      handlers = [Authly::Handler::Bearer.new, ClaimsEcho.new] of HTTP::Handler

      BearerSpec.with_server(handlers) do |client|
        BearerSpec.get(client, "/", "Bearer #{token}").status_code.should eq 200

        other = OpenSSL::PKey::RSA.new(2048)
        forged = JWT.encode(BearerSpec.payload, other.to_pem, JWT::Algorithm::RS256)
        BearerSpec.get(client, "/", "Bearer #{forged}").status_code.should eq 401
        hs_confusion = JWT.encode(BearerSpec.payload, rsa.public_key.to_pem, JWT::Algorithm::HS256)
        BearerSpec.get(client, "/", "Bearer #{hs_confusion}").status_code.should eq 401
      end
    end
  end
end
