require "rubygems"
require "bundler"
require "logger"
Bundler.require

# add require_relative
unless Kernel.respond_to?(:require_relative)
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller[0]), path.to_str)
    end
  end
end

require_relative 'tagserver'
require_relative 'config_helper'

config = ConfigHelper.load_config("config/database.yml")
service_config = ConfigHelper.load_config("config/services.yml")
grants_config = ConfigHelper.load_config("config/grants.yml")

def mysql_connect_string(config, environment)
  db_config = config[environment]
  port_string = db_config[:port]
  if port_string
    port_string = ":#{port_string}"
  end
  # user:password@host[:port]/database
  "#{db_config[:user]}:#{db_config[:password]}@#{db_config[:host]}#{port_string}/#{db_config[:database]}"
end

configure :test do
  puts 'Test configuration in use'
  DataMapper.setup(:default, "sqlite::memory:")
  DataMapper.auto_migrate!

  AuthService = Object.new
  GRANTS = {}
end

configure :development do
  puts 'Development configuration in use'
  DataMapper.setup(:default, "mysql://#{mysql_connect_string(config, :development)}?encoding=UTF-8")
  DataMapper.auto_upgrade!

  AuthService = RestClient::Resource.new(service_config[:development][:authservice])
  GRANTS = grants_config
end

configure :production do
  puts 'Production configuration in use'
  DataMapper.setup(:default, "mysql://#{mysql_connect_string(config, :production)}?encoding=UTF-8")
  DataMapper.auto_upgrade!

  AuthService = RestClient::Resource.new(service_config[:production][:authservice])
  GRANTS = grants_config
end
