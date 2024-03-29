require "./spec_helper"

module Authly
  describe Code do
    context "when request is authorized" do
      it "creates a temporary code request object" do
        auth_code = Code.new(
          "challenge",
          "S256",
          "read",
          "user_id",
          "redirect_uri",
          "client_id"
        )

        auth_code.should be_a Code
        auth_code.code.should_not be_empty
      end
    end
  end
end
