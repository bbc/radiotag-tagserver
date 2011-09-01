# add require_relative
unless Kernel.respond_to?(:require_relative)
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller[0]), path.to_str)
    end
  end
end

require 'rubygems'
# initialize load path ~before~ calling Bundler.require (so set for all gems)
require './lib/load_path'
LoadPath.base_path = File.expand_path(File.join(File.dirname(__FILE__)))

require 'bundler'

Bundler.require

require './lib/init'
require './lib/rewrite_path_info'
use RewritePathInfo
require './lib/trial_logger'
use TrialLogger
run TagServer
