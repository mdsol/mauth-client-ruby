class CanonicalString < String
  def initialize(http_verb, requested_url, post_data)
    super
    @http_verb, @requested_url, @post_data = http_verb, requested_url, post_data
    build
  end

  private
  # Build the canonical string using baroque rules
  def build
    self << "#{verb}\n"
    self << "#{requested_url}\n"
    self << "#{encode_post_data(post_data)}\n" unless post_data.blank?
  end

  # Encode post data using baroque rules
  def encode_post_data(post_data)
    "fancy"
  end

end
