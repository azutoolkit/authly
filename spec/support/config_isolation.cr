# Every example starts with the configuration the suite set up and leaves it that way, so a spec that swaps a store,
# a limiter or the client list cannot leak into the specs that run after it (the order may be random).
class Authly::Configuration
  # Takes over every setting of `from`; lists are copied, since a spec may append to one in place.
  def restore(from : Configuration) : Nil
    {% for ivar in @type.instance_vars %}
      {% if ivar.type <= Array %}
        @{{ ivar.id }} = from.@{{ ivar.id }}.dup
      {% else %}
        @{{ ivar.id }} = from.@{{ ivar.id }}
      {% end %}
    {% end %}
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
