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

These properties are all overriden by command line options.

Currently, it does not support file uploads and websockets. With the addition of these two it will be ready to move to version 1.0

Use it by itself,

or behind nginx -

    upstream www.server.com {
      server 127.0.0.1:3002;
      keepalive 8;
    }
    
    server {
      listen 80
      server_name  .server.com;
      
        location / {
            proxy_pass http://www.server.com;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }    
    }
        
    
    