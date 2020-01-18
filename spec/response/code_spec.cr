require "../spec_helper"

module Authly
  describe Response::Code do
    context "when request is authorized" do
      code = Token::Code.new("1", "uri", "state", "scope").to_s

      it "creates a temporary code request object" do
        auth_code = Response::Code.new(code.to_s, "state")

        auth_code.should be_a Response::Code
        auth_code.state.should eq "state"
        auth_code.code.should eq code
      end
    end
  end
end
