#!/usr/bin/env ruby
# frozen_string_literal: true

abort "USAGE: ./#{__FILE__} <SEARCH TERM>" unless ARGV.size == 1

require 'bundler/setup'
Bundler.require(:default)

# get country information
def get_country_info(search_term)
  get_data_from_references "countries.json?search_term=#{search_term}"
end

# fetch data from References
def get_data_from_references(resource_name)
  puts "fetching #{resource_name}..."
  mauth_config = MAuth::ConfigEnv.load
  references_host = ENV.fetch('REFERENCES_HOST', 'https://references-innovate.imedidata.com')
  begin
    connection = Faraday::Connection.new(url: references_host) do |builder|
      builder.use MAuth::Faraday::RequestSigner, mauth_config
      builder.adapter Faraday.default_adapter
    end

    # get the data
    response = connection.get "/v1/#{resource_name}"
    puts "HTTP #{response.status}"

    # return the user info
    if response.status == 200
      result = JSON.parse(response.body)
      puts JSON.pretty_generate(result)
      result
    else
      puts response.body
      nil
    end
  rescue JSON::ParserError => e
    puts "Error parsing data from references: #{e.inspect}"
    puts e.backtrace.join("\n")
  end
end

get_country_info(ARGV[0])
