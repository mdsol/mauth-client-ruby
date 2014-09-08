require 'rubygems'
require 'bundler'
require 'kender/tasks'

begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end
require 'rake'

task :default => :test

namespace :test do
  require 'rspec/core/rake_task'
  RSpec::Core::RakeTask.new(:rspec)
end
task :test => 'test:rspec'

task :shamus do
  STDOUT.puts 'Generating validation documents'
  system 'shamus'

  if File.exists?('coverage')
    STDOUT.puts 'Adding coverage report'
    FileUtils.copy_entry('coverage', 'columbo/coverage')

    require 'nokogiri'
    filename = File.expand_path(File.join(File.dirname(__FILE__), 'columbo/index.html'))
    doc = Nokogiri::HTML(open(filename))
    link_list = doc.css('ul').first
    link = Nokogiri::XML::Node.new "a", doc
    link.content = 'Coverage'
    link['href'] = 'coverage/index.html'
    li = Nokogiri::XML::Node.new "li", doc
    li.add_child(link)
    link_list.add_child(li)

    File.open(filename, 'w') { |f| f.puts doc.to_s }
  end
end
