#
# httpserver.rb -- HTTPServer Class
#
# Author: IPR -- Internet Programming with Ruby -- writers, Pradeep Singh
# Copyright (c) 2000, 2001 TAKAHASHI Masayoshi, GOTOU Yuuzou
# Copyright (c) 2002 Internet Programming with Ruby writers
# Copyright (c) 2012 Pradeep Singh
# All rights reserved.

require 'socket'
require 'webricknio/config'
require 'webrick/log'
require 'webricknio/log'
require 'webricknio/httprequest'
require 'webricknio/httpresponse'
require 'webrick/server'

require 'webricknio/accesslog'

require 'webricknio/block'

require 'set'

require 'java'

java_import 'java.nio.ByteBuffer'

java_import 'java.nio.channels.ServerSocketChannel'
java_import 'java.nio.channels.Selector'
java_import 'java.nio.channels.SelectionKey'

java_import 'java.net.ServerSocket'
java_import 'java.net.InetSocketAddress'

java_import 'java.util.Iterator'

module WEBrickNIO

  class HTTPServer
    attr_reader :status, :config, :logger, :selector

    def initialize(config={}, default=Config::HTTP)

      begin
        file_name = "#{Rails.root}/config/webricknio.rb"
        file = File.open(file_name, 'r')
        hash = eval file.read
        @config = default.update(hash).update(config)
      rescue
        @config = default.dup.update(config)
        puts "custom config file not present"
      end

      @config[:Logger] ||= ::WEBrickNIO::Log::new @config[:LogLocation]
      @logger = @config[:Logger]
      @logger.level = @config[:LogLevel] if @config[:LogLevel]

      @logger.info "configured properties:\n#{@config}"

      @status = :Stop

      poolv = WEBrickNIO::VERSION
      rubyv = "#{RUBY_VERSION} (#{RUBY_RELEASE_DATE}) [#{RUBY_PLATFORM}]"
      @logger.info("HTTPServerNIO #{poolv}")
      @logger.info("ruby #{rubyv}")

      @mount_tab = MountTable.new

      unless @config[:AccessLog]
        @config[:AccessLog] = [
            [ $stderr, ::WEBrickNIO::AccessLog::COMMON_LOG_FORMAT ],
            [ $stderr, ::WEBrickNIO::AccessLog::REFERER_LOG_FORMAT ]
        ]
      end

      @blocker_chain = WEBrickNIO::ChainedBlock.new

      trap(:INT) do
        @logger.info "SIGINT in WEBrickNIO::HTTPServer"
        shutdown
      end

      trap(:HUP) do
        @logger.info "SIGHUP in WEBrickNIO::HTTPServer"
        reload
      end
    end

    def reload
      @blocker_chain.reload
    end


    def start(&block)
      raise ::WEBrick::ServerError, "already started." if @status != :Stop
      @logger.info \
          "#{self.class}#start: pid=#{$$} port=#{@config[:Port]}"

      @server_socket_channel = ServerSocketChannel.open
      @server_socket_channel.configure_blocking false

      sock_addr = InetSocketAddress.new(@config[:Port])
      server_sock = @server_socket_channel.socket.bind sock_addr
      @logger.info "bound socket #{@server_socket_channel.socket.object_id}"

      @selector = Selector.open
      @main_selector_key = @server_socket_channel.register(@selector, SelectionKey::OP_ACCEPT);
      @logger.info "registered selector"

      @thread_pool = java.util.concurrent.Executors.newFixedThreadPool(@config[:NumThreads])
      @logger.info "creating thread pool of size #{@config[:NumThreads]}"

      @status = :Running
      while @status == :Running

        begin
          @selector.select  # go ahead and block here forever
          ready_keys = @selector.selected_keys
        rescue Exception => ex
          if @status == :Running
            @logger.error "SELECTOR exception: #{ex.java_class.name}"
            #ex.print_stack_trace
          else
            @logger.info "selector shutdown"
          end
          next
        end

        begin
          iterator = ready_keys.iterator

          while iterator.has_next
            key = iterator.next
            iterator.remove

            if key.is_valid && key.is_acceptable
              client_channel = @server_socket_channel.accept
              client_channel.configure_blocking false
              sock = client_channel.socket
              remote_addr = sock.getInetAddress
              @logger.info "accepted connection from: #{remote_addr.getHostAddress}"
              if @blocker_chain.block_ip? remote_addr.getHostAddress
                @logger.info "blocked ip: #{remote_addr.getHostAddress}"
                client_channel.close
              else
                key2 = client_channel.register(@selector, SelectionKey::OP_READ, Attachment.new)
              end
            elsif key.is_valid && key.is_readable
              unless key.attachment.is_locked?
                key.attachment.lock
                sock = key.channel.socket
                sock_channel = key.channel
                @thread_pool.submit key.attachment.handler.new(key, self, @config, key.attachment)
              end
            else
              key.cancel
            end

          end # while  iterator

        rescue Exception => ex # to get rid of canceled key exception
          if ex.is_a?(Exception)
            @logger.error(ex)
          else
            message = ""
            if ex.respond_to?(:java_class) && ex.respond_to?(:stack_trace)
              #ex.print_stack_trace
              message += ex.java_class.name + ": " unless ex.java_class.name.nil?
            else
              message = ex.inspect
            end
            @logger.error(message)
          end
        end

      end # while   Running

      @logger.info "going to shutdown ..."
      @logger.info "#{self.class}#start done."
      @status = :Stop
      shutdown if @status != :Shutdown
    end

    #
    # Maintains state information for a socket while processing requests.
    # #cleanup needs to be called after every finished processing of a request for a socket
    #

    class Attachment
      attr_accessor :request, :response, :handler

      def initialize
        cleanup
      end

      def lock
        @locked = true
      end

      def unlock
        @locked = false
      end

      def is_locked?
        @locked
      end

      def cleanup

        # This is not a synchronization lock.
        # It is there only to block the flood of signals generated when an event occurs.
        @locked = false

        # Handler that will process requests coming on this socket.
        # Default is RequestHandler which assumes a regular HTTP request. In some cases, such as websockets, handler can be changed
        # to some other class after initial negotiation has been completed using the default handler.
        @handler = RequestHandler

        @request = nil
        @response = nil
      end

    end


    #
    # Instances of this class are submitted to the threadpool to process incoming requests.
    # It will very likely process the whole request in one shot but it might postpone the request too for a slow client
    #

    class RequestHandler
      include java.util.concurrent.Callable

      def initialize(key, server, config, attachment)
        @key = key
        @sock_channel = @key.channel
        @config = config
        @server = server
        @send_response = true
        @socket_id = -1
        @attachment = attachment
      end

      def call
        begin
          time1 = Time.now
          req = @attachment.request || ::WEBrickNIO::HTTPRequest.new(@config)
          res = @attachment.response || ::WEBrickNIO::HTTPResponse.new(@config)

          @socket_id = @sock_channel.socket.object_id

          socket = @sock_channel.socket

          if req.in_progress?
            @server.logger.debug "resuming request in progress"
            req.resume
          else
            # fresh request
            req.parse(@sock_channel)
          end

          if req.in_progress?
            @server.logger.debug "request in progress"
            @attachment.request = req if @attachment.request.nil?
            @attachment.response = res if @attachment.response.nil?
            @send_response = false
            return # goes to "ensure" first
          end

          res.request_method = req.request_method
          res.request_uri = req.request_uri
          res.request_http_version = req.http_version
          res.keep_alive = req.keep_alive?

          if req.unparsed_uri == "*"
            if req.request_method == "OPTIONS"
              do_OPTIONS(req, res)
              raise ::WEBrick::HTTPStatus::OK
            end
            raise ::WEBrick::HTTPStatus::NotFound, "`#{req.unparsed_uri}' not found."
          end

          servlet, options, script_name, path_info = @server.search_servlet(req.path)
          raise ::WEBrick::HTTPStatus::NotFound, "`#{req.path}' not found." unless servlet
          req.script_name = script_name
          req.path_info = path_info
          si = servlet.get_instance(self, *options)
          #@server.logger.debug(format("%s is invoked.", si.class.name))
          @server.access_log(@config, req, res)

          si.service(req, res)

        rescue ::WEBrick::HTTPStatus::EOFError => ex
          @send_response = false
          @attachment.cleanup
          @server.logger.debug(ex.message)
        rescue ::WEBrick::HTTPStatus::Error => ex
          @server.logger.error(ex)
          res.set_error(ex)
        rescue ::WEBrick::HTTPStatus::Status => ex
          res.status = ex.code
        rescue StandardError => ex
          @server.logger.error(ex)
          res.set_error(ex)
        rescue Exception => ex
          if ex.is_a?(Exception)
            @server.logger.error(ex)
          else
            message = ""
            if ex.respond_to?(:java_class) && ex.respond_to?(:stack_trace)
              @server.logger.error("error")
              ex.print_stack_trace
            else
              message = ex.inspect
            end
            @server.logger.error(message)
          end
          res.set_error("500")
        ensure
          begin
            time3 = Time.now
            @attachment.unlock
            if @send_response
              @attachment.cleanup
              res.send_response(@sock_channel)
              @server.logger.debug "time taken to send response #{Time.now - time3}"
            end
            if (!req.keep_alive? || !res.keep_alive? || (!@send_response && !req.in_progress?))
              @server.logger.debug("closing socket. req.keep alive: #{req.keep_alive}, resp.keep alive: #{res.keep_alive}, send_response: #{@send_response}, socket id: #{@socket_id}")
              @sock_channel.close
              @key.cancel
            end
          rescue Exception => ex
            if ex.is_a?(Exception)
              @server.logger.error(ex)
            else
              message = ""
              if ex.respond_to?(:java_class) && ex.respond_to?(:stack_trace)
                @server.logger.error("error")
                ex.print_stack_trace
              else
                message = ex.inspect
              end
              @server.logger.error(message)
            end
          end
          time2 = Time.now
          @server.logger.info "total request time: #{time2 - time1} sec" if @send_response
        end
      end

    end

    #
    # TBD
    #

    class WebsocketHandler
      include java.util.concurrent.Callable

      def initialize(key, server, config, attachment)
        @key = key
        @sock_channel = @key.channel
        @config = config
        @server = server
        @send_response = true
        @socket_id = -1
        @attachment = attachment
      end

      def call
      end

    end


    def stop
      if @status == :Running
        @status = :Shutdown
      end
    end

    def shutdown
      stop
      @server_socket_channel.close
      @selector.close
      @thread_pool.shutdown
      @logger.debug "shutdown thread pool"
    end

    def [](key)
      @config[key]
    end



    def do_OPTIONS(req, res)
      res["allow"] = "GET,HEAD,POST,OPTIONS"
    end

    ##
    # Mounts +servlet+ on +dir+ passing +options+ to the servlet at creation
    # time

    def mount(dir, servlet, *options)
      @logger.debug(sprintf("%s is mounted on %s", servlet.inspect, dir))
      @mount_tab[dir] = [ servlet, options ]
    end

    ##
    # Mounts +proc+ or +block+ on +dir+ and calls it with a
    # WEBrick::HTTPRequest and WEBrick::HTTPResponse

    def mount_proc(dir, proc=nil, &block)
      proc ||= block
      raise HTTPServerError, "must pass a proc or block" unless proc
      mount(dir, HTTPServlet::ProcHandler.new(proc))
    end

    ##
    # Unmounts +dir+

    def unmount(dir)
      @logger.debug(sprintf("unmount %s.", dir))
      @mount_tab.delete(dir)
    end
    alias umount unmount

    ##
    # Finds a servlet for +path+

    def search_servlet(path)

      script_name, path_info = @mount_tab.scan(path)
      servlet, options = @mount_tab[script_name]
      if servlet
        [ servlet, options, script_name, path_info ]
      end
    end

    def access_log(config, req, res)
      param = ::WEBrickNIO::AccessLog::setup_params(config, req, res)
      @config[:AccessLog].each{|logger, fmt|
        logger << ::WEBrickNIO::AccessLog::format(fmt+"\n", param)
      }
    end

    class MountTable
      def initialize
        @tab = Hash.new
        compile
      end

      def [](dir)
        dir = normalize(dir)
        @tab[dir]
      end

      def []=(dir, val)
        dir = normalize(dir)
        @tab[dir] = val
        compile
        val
      end

      def delete(dir)
        dir = normalize(dir)
        res = @tab.delete(dir)
        compile
        res
      end

      def scan(path)
        @scanner =~ path
        [ $&, $' ]
      end

      private

      def compile
        k = @tab.keys
        k.sort!
        k.reverse!
        k.collect!{|path| Regexp.escape(path) }
        @scanner = Regexp.new("^(" + k.join("|") +")(?=/|$)")
      end

      def normalize(dir)
        ret = dir ? dir.dup : ""
        ret.sub!(%r|/+$|, "")
        ret
      end
    end

    private
      MAX_URI_LENGTH = 2083

  end
end