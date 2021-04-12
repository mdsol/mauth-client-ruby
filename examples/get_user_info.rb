#!/usr/bin/env ruby

abort "USAGE: ./#{__FILE__} <USER UUID>" unless ARGV.size == 1

require 'bundler/setup'
Bundler.require(:default)

def config
  @conf ||= YAML.load(File.open("./config.yml"))
end

# get user information
def get_user_info_mauth(user_uuid)
  get_data_from_imedidata "users/#{user_uuid}.json"
end

# fetch data from iMedidata
def get_data_from_imedidata(resource_name)
  puts "fetching #{resource_name}..."
  begin
    connection = Faraday::Connection.new(url: config["imedidata"]["host"]) do |builder|
      builder.use Mauth::Faraday::RequestSigner, config["mauth"]
      builder.adapter Faraday.default_adapter
    end

    # get the data
    response = connection.get "/api/v2/#{resource_name}"
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
    puts "Error parsing data from imedidata: #{e.inspect}"
    puts e.backtrace.join("\n")
  end
end

get_user_info_mauth(ARGV[0])


### OTHER EXAMPLES

#### get study groups for an user
def get_study_groups_mauth(user_uuid)
 get_data_from_imedidata "users/#{user_uuid}/study_groups.json"
end

#### get roles for a user in an application study
def get_user_study_roles_mauth(user_uuid, study_uuid)
 get_data_from_imedidata "users/#{user_uuid}/studies/#{study_uuid}/apps/#{config["mauth"]["app_uuid"]}/roles.json"
end
