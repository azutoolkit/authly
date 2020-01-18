require "./spec_helper"

module Authly
  describe ResponseStrategy do
    client_id = "1"
    state = "state"
    scope = "scope"
    redirect_uri = "https://www.example.com/callback"

    describe ".strategy" do
      it "returns a Response::Code" do
        strategy = ResponseStrategy.parse("code").strategy(
          client_id: client_id,
          redirect_uri: redirect_uri,
          scope: scope,
          state: state
        )

        strategy.should be_a Response::Code
      end

      it "returns a Response::AccessToken" do
        strategy = ResponseStrategy.parse("token").strategy(
          client_id: client_id,
          redirect_uri: redirect_uri,
          scope: scope,
          state: state
        )

        strategy.should be_a Response::AccessToken
      end
    end
  end
end
