**Summary** -

Use WEBrickNIO as highly scalable server for JRuby apps. Taking advantage of JRuby, WEBrick’s code has been littered with Java NIO code and the result is WEBrickNIO. epoll and thread pool have been added to WEBrickNIO so that it uses the same technology that make eventmachine and nginx so scalable.

One server is all you need, configure as many threads as your machine can run, no need for any cluster (on one machine that is).

- - -

**Installation** -

In your Gemfile -

    gem "webricknio", "~> 0.6.0"

then -

    bundle install

This will install webricknio-{version}.gem

To run, at your rails root -

    rails s wnio

To get the configuration file in your config directory -

    rails g webricknio 
    
- this creates a file webricknio.rb in the 'config' directory (not in config/initialzers)

Some properties of inerest in the config file -

    :LogLevel       => ::WEBrick::Log::DEBUG
    :NumThreads     => 10,

Options passed through command line override these properties (such as port number).

Currently, it does not support file uploads and websockets. With the addition of these two it will be ready to move to version 1.0

Use it by itself (in which case it will have to be run as root if it must bind to port 80, because JRuby can't spawn),

Or behind nginx -

    upstream www.server.com {
      server 127.0.0.1:3002;
      keepalive 8;
    }
    
    server {
      listen 80
      server_name  .server.com;
      
        location / {
            proxy_set_header X-Real-IP $remote_addr;            
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_pass http://www.server.com;
        }    
    }
        
- - -
[Blocking IP addresses](https://github.com/pksinghus/webricknio/wiki/Blocking-IP-addresses)
- - - 

For more information on technology, check out -
[Why WEBrickNIO](http://www.pradeeplogs.com/items/1-why-webricknio)
    