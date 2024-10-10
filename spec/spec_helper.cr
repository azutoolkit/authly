require "spec"
require "digest"
require "base64"
require "faker"
require "../src/authly"
require "./support/settings"

process = nil
Spec.before_suite do
  # Start test server
  process = Process.new("bin/test_server", output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
  # Wait for process to start
  sleep 1.seconds
end

Spec.after_suite do
  # Stop test server
  if pro = process
    pro.terminate
    sleep 1.seconds
  end
end
