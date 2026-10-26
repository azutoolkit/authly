# Every example starts with the configuration the suite set up and leaves it that way, so a spec that assigns a
# setting (a store, a limiter, a hook) or appends to the client list or an Array setting cannot leak into the specs that
# run after it (the order may be random). What is NOT isolated: the contents of the stores and limiters themselves. A
# spec that writes into the shared default store (tokens, device codes, counters) leaves them there; assign a fresh
# one first, as `DeviceSpec.fresh` does.
class Authly::Configuration
  # Takes over every setting of `from`; lists are copied, since a spec may append to one in place.
  def restore(from : Configuration) : Nil
    {% for ivar in @type.instance_vars %}
      {% if ivar.type <= Array %}
        @{{ ivar.id }} = from.@{{ ivar.id }}.dup
      {% elsif ivar.id == "clients" %}
        @clients = copy_of(from.@clients)
      {% else %}
        @{{ ivar.id }} = from.@{{ ivar.id }}
      {% end %}
    {% end %}
  end

  # The client list is an object of its own, so copying the reference would share what `clients << client` appends.
  private def copy_of(clients : AuthorizableClient) : AuthorizableClient
    return clients unless clients.is_a?(Clients)

    copy = Clients.new
    clients.each { |client| copy << client }
    copy
  end

  def snapshot : Configuration
    copy = Configuration.allocate
    copy.restore(self)
    copy
  end
end

Spec.around_each do |example|
  saved = Authly.config.snapshot
  begin
    example.run
  ensure
    Authly.config.restore(saved)
  end
end
