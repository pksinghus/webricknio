#--
# block.rb
#
# Author: Pradeep Singh
# Copyright (c) 2012 Pradeep Singh
# All rights reserved.

require 'java'

require 'yaml'

module WEBrickNIO

  class BaseBlock
    def initialize(options = {})
      @logger = options["logger"] || FakeLogger.new
    end
    def valid?(ip)
      raise "valid? Not implemented"
    end
    def add_ip(ip)
      raise "add_ip Not implemented"
    end
    def block_ip?(ip)
      raise "block_ip? Not implemented"
    end
    def self.inherited(subclass)
      subclass.instance_eval {
        alias old_new new
        def new
          alias_method :matches?, :block_ip?
          old_new
        end
      }
    end
  end

  #
  # Wrapper that chains other blockers
  #

  class ChainedBlock < BaseBlock

    def initialize(options = {})
      begin
        load
      rescue Exception => ex
        puts ex
        create_default_chain
      end

      super

      at_exit do
        file = File.new(File.expand_path('block.yaml', File.dirname(__FILE__)), "w")
        dump = YAML::dump(@chain)
        file.write(dump)
        file.close
      end
    end

    def load
      file = File.new(File.expand_path('block.yaml', File.dirname(__FILE__)), "r")
      @chain = YAML::load(file)
      ensure_default_chain @chain
      puts @chain
    end

    def reload
      load
    end

    def add_ip(ip)
      @chain.each do |blocker|
        if blocker.valid? ip
          blocker.add_ip ip
          return true
        end
      end
      return false
    end

    def block_ip?(ip)
      @chain.each do |blocker|
        if blocker.block_ip?(ip)
          return true
        end
      end
      return false
    end

    private

    def create_default_chain
      @chain = []
      add_chain_elements @chain
    end

    def add_chain_elements(arr)
      arr << PrefixBlock.new
      arr << ListBlock.new
      arr
    end

    def ensure_default_chain(chain)
      if chain.nil? || !chain.is_a?(Array)
        create_default_chain
      elsif chain.length == 0
        add_chain_elements chain
      elsif chain.length == 1
        if chain[0].class.name == "WEBrickNIO::PrefixBlock"
          chain << ListBlock.new
        elsif chain[0].class.name == "WEBrickNIO::ListBlock"
          chain << PrefixBlock.new
        end
      end
    end

  end


  #
  # Blocks IPs with given prefix
  #

  class PrefixBlock < BaseBlock

    def initialize(options = {})
      @block_list = options["block_list"] || []
      super
    end

    def self.from_array(arr)
      blocker = self.new
      block_list = []
      arr.each do |item|
        blocker.add_ip item.to_s
      end unless arr.nil?
      blocker
    end

    def block_ip?(ip)
      @block_list.each do |item|
        if ip.start_with? item
          @logger.info "ip matches: PrefixBlock - #{ip}"
          return true
        end
      end
      return false
    end

    def valid?(ip)
      ip.split(".").size <= 3
    end

    def add_ip(ip)
      return false if ip.nil? || ip.strip.length == 0
      if valid?(ip) && !@block_list.include?(ip)
        @block_list << ip
        true
      else
        false
      end
    end

    def to_yaml( opts = {} )
      YAML.quick_emit( nil, opts ) { |out|
        out.map("!IPBlockerPrefixBlock,1234/PrefixBlock" ) { |map|
          map.add("block_list", @block_list)
        }
      }
    end

    def to_s
      "PrefixBlock<#{object_id}>:#{@block_list}"
    end

  end


  #
  # Blocks IPs that are exact match
  #

  class ListBlock < BaseBlock

    def initialize(options = {})
      @block_list = options["block_list"] || java.util.concurrent.ConcurrentSkipListSet.new
      super
    end

    def self.from_array(arr)
      blocker = self.new
      arr.each do |item|
        blocker.add_ip item.to_s
      end unless arr.nil?
      blocker
    end

    def block_ip?(ip)
      if @block_list.include? ip
        @logger.info "ip matches: ListBlock - #{ip}"
        true
      else
        false
      end
    end

    def valid?(ip)
      ip.split(".").size > 3
    end

    def add_ip(ip)
      return false if ip.nil? || ip.strip.length == 0
      if valid? ip
        @block_list.add ip
        true
      else
        false
      end
    end

    def to_yaml( opts = {} )
      YAML.quick_emit( nil, opts ) { |out|
        out.map("!IPBlockerListBlock,1234/ListBlock" ) { |map|
          map.add("block_list", @block_list.to_a)
        }
      }
    end

    def to_s
      "ListBlock<#{object_id}>:#{@block_list.to_a}"
    end

  end



  YAML::add_domain_type("IPBlockerListBlock,1234", "ListBlock") do |type, val|
    ListBlock.from_array(val["block_list"])
  end

  YAML::add_domain_type("IPBlockerPrefixBlock,1234", "PrefixBlock") do |type, val|
    PrefixBlock.from_array(val["block_list"])
  end



  class FakeLogger
    def method_missing(method, *args, &block)
      puts args
    end
  end

end

#chain = WEBrickNIO::ChainedBlock.new

#ip ="180.76"
#chain.add(ip)

#ip ="92.240.68.152"
#chain.add(ip)
#ip ="180.76"
#chain.block_ip? ip

#ip ="92.240.68.152"
#chain.matches? ip



