require 'rubygems'

spec = Gem::Specification.new do |s|
  s.name = 'webricknio'
  s.version = '0.5.0'
  s.summary = "WEBrick with NIO"
  s.files = Dir.glob("**/**/**")
  s.test_files = Dir.glob("test/*_test.rb")
  s.author = "Pradeep Singh"
  s.email = "pradeep@pradeeplogs.com"
  s.has_rdoc = false
  s.required_ruby_version = '>= 1.9.1'
end
