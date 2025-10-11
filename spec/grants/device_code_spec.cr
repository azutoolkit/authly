require "../spec_helper"

module Authly
  describe DeviceCode do
    client_id = "1"
    scope = "read"

    describe ".create_device_authorization" do
      it "creates device authorization with valid data" do
        device_data = DeviceCode.create_device_authorization(client_id, scope)

        device_data.should be_a DeviceCodeData
        device_data.device_code.should_not be_empty
        device_data.user_code.should_not be_empty
        device_data.client_id.should eq client_id
        device_data.scope.should eq scope
        device_data.verified.should be_false
      end

      it "generates properly formatted user code" do
        device_data = DeviceCode.create_device_authorization(client_id, scope)

        # User code should be in format XXXX-XXXX
        device_data.user_code.should match(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/)
      end

      it "stores device authorization in store" do
        device_data = DeviceCode.create_device_authorization(client_id, scope)

        stored_data = Authly.config.device_code_store.fetch(device_data.device_code)
        stored_data.should_not be_nil
        stored_data.try(&.device_code).should eq device_data.device_code
      end
    end

    describe "#authorized?" do
      it "returns false when device code is not verified" do
        device_data = DeviceCode.create_device_authorization(client_id, scope)
        device_code_grant = DeviceCode.new(client_id, device_data.device_code)

        expect_raises Error, ERROR_MSG[:authorization_pending] do
          device_code_grant.authorized?
        end
      end

      it "returns true when device code is verified" do
        device_data = DeviceCode.create_device_authorization(client_id, scope)

        # Manually verify the device code
        device_data.verified = true
        device_data.user_id = "test_user"
        Authly.config.device_code_store.update(device_data.device_code, device_data)

        device_code_grant = DeviceCode.new(client_id, device_data.device_code)
        device_code_grant.authorized?.should be_true
      end

      it "raises error for invalid device code" do
        device_code_grant = DeviceCode.new(client_id, "invalid_device_code")

        expect_raises Error, ERROR_MSG[:invalid_grant] do
          device_code_grant.authorized?
        end
      end

      it "raises error for mismatched client_id" do
        device_data = DeviceCode.create_device_authorization(client_id, scope)
        device_data.verified = true
        Authly.config.device_code_store.update(device_data.device_code, device_data)

        device_code_grant = DeviceCode.new("wrong_client_id", device_data.device_code)

        expect_raises Error, ERROR_MSG[:invalid_grant] do
          device_code_grant.authorized?
        end
      end
    end

    describe "device code store" do
      it "fetches by user code" do
        device_data = DeviceCode.create_device_authorization(client_id, scope)

        stored_data = Authly.config.device_code_store.fetch_by_user_code(device_data.user_code)
        stored_data.should_not be_nil
        stored_data.try(&.device_code).should eq device_data.device_code
      end

      it "updates device code data" do
        device_data = DeviceCode.create_device_authorization(client_id, scope)

        device_data.verified = true
        device_data.user_id = "test_user"
        Authly.config.device_code_store.update(device_data.device_code, device_data)

        updated_data = Authly.config.device_code_store.fetch(device_data.device_code)
        updated_data.should_not be_nil
        updated_data.try(&.verified).should be_true
        updated_data.try(&.user_id).should eq "test_user"
      end

      it "deletes device code" do
        device_data = DeviceCode.create_device_authorization(client_id, scope)

        Authly.config.device_code_store.delete(device_data.device_code)

        stored_data = Authly.config.device_code_store.fetch(device_data.device_code)
        stored_data.should be_nil
      end
    end
  end
end

