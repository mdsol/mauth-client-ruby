# frozen_string_literal: true

require "dice_bag"

class MauthTemplate < DiceBag::AvailableTemplates
  def templates
    ["mauth.yml.dice", "mauth_key.dice"].map do |template|
      File.join(File.dirname(__FILE__), template)
    end
  end
end

class MauthInitializerTemplate < DiceBag::AvailableTemplates
  def templates_location
    "config/initializers"
  end

  def templates
    [File.join(File.dirname(__FILE__), "mauth.rb.dice")] if Object.const_defined?(:Rails)
  end
end
