#--
# webricknio.rb
#
# Author: Pradeep Singh
# Copyright (c) 2012 Pradeep Singh
# All rights reserved.

General = {
    :ServerName     => ::WEBrick::Utils::getservername,
    :BindAddress    => nil,   # "0.0.0.0" or "::" or nil
    :Port           => nil,   # users MUST specify this!!
    :MaxClients     => 100,   # maximum number of the concurrent connections
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

HTTP = General.dup.update(
    :Port           => 80,
    :RequestTimeout => 5,
    :NumThreads     => 20,
    :HTTPVersion    => ::WEBrick::HTTPVersion.new("1.1"),
    :AccessLog      => nil,
    :LogLocation    => nil, #"log/webrick.log"
    :LogLevel       => ::WEBrick::Log::INFO,
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
