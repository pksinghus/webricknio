require 'rubygems'

spec = Gem::Specification.new do |s|
  s.name = 'webricknio'
  s.description = 'WEBrick with Java NIO, uses epoll and thread pool for scalability'
  s.version = '0.6.0'
  s.summary = "WEBrick with NIO"
  s.files = Dir.glob("**/**/**")
  s.test_files = Dir.glob("test/*_test.rb")
  s.author = "Pradeep Singh"
  s.email = "pradeep@pradeeplogs.com"
  s.has_rdoc = false
  s.required_ruby_version = '>= 1.9.1'
  s.homepage = 'https://github.com/pksinghus/webricknio'
end
