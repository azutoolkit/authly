require "./spec_helper"

describe "Spec configuration isolation" do
  it "takes back a client appended to the shared list" do
    saved = Authly.config.snapshot
    Authly.config.clients << Authly::Client.new("Leaky", "s", "https://leak.example/cb", "leaky-client")
    Authly.config.clients.valid_redirect?("leaky-client", "https://leak.example/cb").should be_true

    Authly.config.restore(saved)
    Authly.config.clients.valid_redirect?("leaky-client", "https://leak.example/cb").should be_false
  end
end
