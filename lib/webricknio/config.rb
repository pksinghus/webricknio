#
# config.rb -- Default configurations.
#
# Author: IPR -- Internet Programming with Ruby -- writers
# Copyright (c) 2000, 2001 TAKAHASHI Masayoshi, GOTOU Yuuzou
# Copyright (c) 2003 Internet Programming with Ruby writers. All rights
# reserved.
#
# $IPR: config.rb,v 1.52 2003/07/22 19:20:42 gotoyuzo Exp $

require 'webricknio/version'
require 'webrick/httpversion'
require 'webrick/httputils'
require 'webrick/utils'
require 'webrick/log'
require 'webricknio/log'

module WEBrickNIO
  module Config
    LIBDIR = File::dirname(__FILE__)

    # for GenericServer
    General = {
      :ServerName     => ::WEBrick::Utils::getservername,
      :BindAddress    => nil,   # "0.0.0.0" or "::" or nil
      :Port           => nil,   # users MUST specify this!!
      :ServerType     => nil,   # default: WEBrick::SimpleServer
      :Logger         => nil,   # default: WEBrick::Log.new
      #:ServerSoftware => "WEBrickNIO/#{WEBrickNIO::VERSION} " +
      #                   "(Ruby/#{RUBY_VERSION}/#{RUBY_RELEASE_DATE})",
      :ServerSoftware => "pks/#{WEBrickNIO::VERSION} ",
      :TempDir        => ENV['TMPDIR']||ENV['TMP']||ENV['TEMP']||'/tmp',
      :DoNotListen    => false,
      :StartCallback  => nil,
      :StopCallback   => nil,
      :AcceptCallback => nil,
      :DoNotReverseLookup => nil,
      :ShutdownSocketWithoutClose => false,
    }

    # for HTTPServer, HTTPRequest, HTTPResponse ...
    HTTP = General.dup.update(
      :Port           => 80,
      :RequestTimeout => 5,
      :NumThreads     => 20,
      :HTTPVersion    => ::WEBrick::HTTPVersion.new("1.1"),
      :AccessLog      => nil,
      :LogLocation    => nil, #"log/webrick.log"
      :LogLevel       => ::WEBrick::Log::DEBUG,
      :MimeTypes      => ::WEBrick::HTTPUtils::DefaultMimeTypes,
      :DirectoryIndex => ["index.html","index.htm","index.cgi","index.rhtml"],
      :DocumentRoot   => nil,
      :DocumentRootOptions => { :FancyIndexing => true },
      :RequestCallback => nil,
      :ServerAlias    => nil,
      :InputBufferSize  => 65536, # input buffer size in reading request body
      :OutputBufferSize => 65536, # output buffer size in sending File or IO

      # for HTTPProxyServer
      :ProxyAuthProc  => nil,
      :ProxyContentHandler => nil,
      :ProxyVia       => true,
      :ProxyTimeout   => true,
      :ProxyURI       => nil,

      :CGIInterpreter => nil,
      :CGIPathEnv     => nil,

      # workaround: if Request-URIs contain 8bit chars,
      # they should be escaped before calling of URI::parse().
      :Escape8bitURI  => false
    )

    FileHandler = {
      :NondisclosureName => [".ht*", "*~"],
      :FancyIndexing     => false,
      :HandlerTable      => {},
      :HandlerCallback   => nil,
      :DirectoryCallback => nil,
      :FileCallback      => nil,
      :UserDir           => nil,  # e.g. "public_html"
      :AcceptableLanguages => []  # ["en", "ja", ... ]
    }

    BasicAuth = {
      :AutoReloadUserDB     => true,
    }

    ##
    # Default configuration for WEBrick::HTTPAuth::DigestAuth.
    #
    # :Algorithm:: MD5, MD5-sess (default), SHA1, SHA1-sess
    # :Domain:: An Array of URIs that define the protected space
    # :Qop:: 'auth' for authentication, 'auth-int' for integrity protection or
    #        both
    # :UseOpaque:: Should the server send opaque values to the client?  This
    #              helps prevent replay attacks.
    # :CheckNc:: Should the server check the nonce count?  This helps the
    #            server detect replay attacks.
    # :UseAuthenticationInfoHeader:: Should the server send an
    #                                AuthenticationInfo header?
    # :AutoReloadUserDB:: Reload the user database provided by :UserDB
    #                     automatically?
    # :NonceExpirePeriod:: How long should we store used nonces?  Default is
    #                      30 minutes.
    # :NonceExpireDelta:: How long is a nonce valid?  Default is 1 minute
    # :InternetExplorerHack:: Hack which allows Internet Explorer to work.
    # :OperaHack:: Hack which allows Opera to work.

    DigestAuth = {
      :Algorithm            => 'MD5-sess', # or 'MD5'
      :Domain               => nil,        # an array includes domain names.
      :Qop                  => [ 'auth' ], # 'auth' or 'auth-int' or both.
      :UseOpaque            => true,
      :UseNextNonce         => false,
      :CheckNc              => false,
      :UseAuthenticationInfoHeader => true,
      :AutoReloadUserDB     => true,
      :NonceExpirePeriod    => 30*60,
      :NonceExpireDelta     => 60,
      :InternetExplorerHack => true,
      :OperaHack            => true,
    }
  end
end
