In your Gemfile -

gem 'webricknio', :git => 'git@github.com:pksinghus/webricknio.git'

then -

bundle install

This will install webricknio-{version}.gem

To run, at your rails root -

rails s wnio

To get the configuration file in your config directory -

rails g webricknio - this creates a file webricknio.rb in the 'config' directory (not in config/initialzers)

Some properties of inerest in the config file -

:LogLevel       => ::WEBrick::Log::DEBUG

:NumThreads     => 10,

These properties are al overriden by command line options.

Currently, it does not support file uploads and websockets. With the addition of these two it will be ready to move to version 1.0
