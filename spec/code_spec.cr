require "./spec_helper"

module Authly
  describe Code do
    context "when request is authorized" do
      it "creates a temporary code request object" do
        auth_code = Code.new("state", "challenge", "S256")

        auth_code.should be_a Code
        auth_code.state.should eq "state"
        auth_code.code.should_not be_empty
      end
    end
  end
end
