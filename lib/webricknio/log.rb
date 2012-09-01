#
# Copyright (c) 2012 Pradeep Singh
#

require 'webrick/log'

module WEBrickNIO

  ##
  # A generic logging class

  class Log < ::WEBrick::Log

    def level=(level)
      @level = level
    end

    # Shortcut for logging a FATAL message
    def fatal(msg) log(FATAL, "FATAL " << format(msg) << ", " << caller[0][caller[0].rindex("/").nil? ? 0 : caller[0].rindex("/") + 1 .. -1]); end
    # Shortcut for logging an ERROR message
    def error(msg) log(ERROR, "ERROR " << format(msg) << ", " << caller[0][caller[0].rindex("/").nil? ? 0 : caller[0].rindex("/") + 1 .. -1]); end
    # Shortcut for logging a WARN message
    def warn(msg)  log(WARN,  "WARN  " << format(msg) << ", " << caller[0][caller[0].rindex("/").nil? ? 0 : caller[0].rindex("/") + 1 .. -1]); end
    # Shortcut for logging an INFO message
    def info(msg)  log(INFO,  "INFO  " << format(msg) << ", " << caller[0][caller[0].rindex("/").nil? ? 0 : caller[0].rindex("/") + 1 .. -1]); end
    # Shortcut for logging a DEBUG message
    def debug(msg) log(DEBUG, "DEBUG " << format(msg) << ", " << caller[0][caller[0].rindex("/").nil? ? 0 : caller[0].rindex("/") + 1 .. -1]); end
  end

end
