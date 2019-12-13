require "../spec_helper"

module Authly
  describe Token do
    cid = "1"
    uri = "http://www.examples.com/callback"
    exp = 1.minute.from_now.to_unix
    scope = "read write"
    state = "d07d3632-4f09-49c2-b6a4-38accec79d68"
    code = Token.write(cid, uri, exp, state, scope)

    it "writes code" do
      payload = {"cid" => cid, "uri" => uri, "exp" => exp, "state" => state, "scope" => scope}
      code.should eq JWT.encode(payload, Authly.secret, JWT::Algorithm::HS256)
    end

    context "with invalid claims" do
      it "raises error if expired" do
        exp = 1.minute.ago.to_unix
        expired_code = Token.write(cid, uri, exp)

        expect_raises JWT::ExpiredSignatureError do
          Token.read(expired_code)
        end
      end
    end
  end
end
