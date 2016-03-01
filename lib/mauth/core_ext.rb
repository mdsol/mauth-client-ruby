class Hash
  # like stringify_keys, but does not attempt to stringify anything other than Symbols.
  # other keys are left alone.
  def stringify_symbol_keys
    inject({}) { |acc, (k, v)| acc.update((k.is_a?(Symbol) ? k.to_s : k) => v) }
  end
end
