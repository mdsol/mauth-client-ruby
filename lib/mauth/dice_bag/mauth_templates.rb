require 'dice_bag'

class MauthTemplate < DiceBag::AvailableTemplates
  def templates
    ['mauth.yml.dice', 'mauth_key.dice'].map do |template|
      File.join(File.dirname(__FILE__), template)
    end
  end
end
