require 'rubygems'
require 'bundler'

Bundler.require

require './lib/init'
require './lib/rewrite_path_info'
use RewritePathInfo
run TagServer
