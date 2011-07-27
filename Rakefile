require 'rake'
require 'rake/testtask'

task :default => [:test]

desc "Run tests"
Rake::TestTask.new("test") { |t|
  t.libs << 'lib'
  t.libs << 'test'
  t.pattern = FileList['test/tagserver_test.rb']
}
