require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'kender/tasks'

RSpec::Core::RakeTask.new(:rspec)

task default: :spec

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
