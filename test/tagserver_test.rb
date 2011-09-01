ENV['RACK_ENV'] = 'test'

require 'init'

require 'test/unit'
require 'rack/test'
require 'pp'
require 'mocha'
require 'shoulda'
require 'json'
require 'fakeweb'

FakeWeb.allow_net_connect = false

GRANTS = {
  'unpaired'     => 'b86bfdfb-5ff5-4cc7-8c61-daaa4804f188',
  'can_register' => 'ddc7f510-9353-45ad-9202-746ffe3b663a'
}

def mock_auth(url, params, code, body = '', method = :post)
  mock_response = stub(:code => code, :body => body)
  mock_resource = mock()
  ::AuthService.expects(:[]).with(url).returns(mock_resource)
  mock_resource.expects(method).with(params).returns(mock_response)
  mock_resource
end

module TestHelpers
  def assert_status(status)
    assert_equal status, last_response.status, "Expected HTTP status #{status} - got #{last_response.status}"
  end

  def assert_response_json_contains(key)
    begin
      data = JSON.parse(last_response.body)
      assert data.key?(key)
    rescue => e
      fail "Not JSON response"
    end
  end

  def assert_has_header(header, content = nil)
    value = last_response.headers[header]
    assert value, "Missing header '#{header}': #{last_response.headers.inspect}"
    assert_equal content, value, "Expected header '#{header}' to be '#{content}' but got '#{last_response.headers[header]}'" if content
  end

  def assert_has_no_header(header)
    assert !last_response.headers[header], "Unexpected header '#{header}': #{last_response.headers.inspect}"
  end

  def assert_atom_feed_entries(number_of_entries)
    doc = Nokogiri::XML(last_response.body)
    assert_equal 0, doc.errors.size
    assert_equal number_of_entries, doc.xpath('//xmlns:entry').size
  end

  def assert_atom_feed_has_entry_for(title)
    doc = Nokogiri::XML(last_response.body)
    assert_equal title, doc.xpath("//xmlns:entry/xmlns:title").first.content
  end
end

class TagServerTest < Test::Unit::TestCase
  include Rack::Test::Methods
  include TestHelpers

  def app
    TagServer
  end

  def assert_has_grant_headers(scope)
    assert_has_header 'X-RadioTAG-Grant-Token'
    assert_has_header 'X-RadioTAG-Grant-Scope', scope
  end

  def assert_has_no_grant_headers()
    assert !last_response.headers['X-RadioTAG-Grant-Token'], "Should not have header: X-RadioTAG-Grant-Token=#{last_response.headers['X-RadioTAG-Grant-Token']}"
    assert !last_response.headers['X-RadioTAG-Grant-Scope'], "Should not have header: X-RadioTAG-Grant-Scope=#{last_response.headers['X-RadioTAG-Grant-Scope']}"
  end

  context "When the server only supports anonymous tagging" do
    # TODO all other endpoints should 404
    setup do
      TagServer.any_instance.stubs(:grants).returns({})
    end

    context "a POST to /tag" do

      setup do
        mock_auth("/authorized", {:token => ""}, 401)
        Solr.expects(:solr_host).at_least_once.returns("solr.example.com")

        FakeWeb.register_uri(:get, %r|http://solr\.example\.com/solr/select.*|,
                             :body => File.read(File.dirname(__FILE__) + '/solr_response.json'))

        post '/tag', {:station=>"0.c224.ce15.ce1.dab", :time => Time.now.utc.to_i}
      end

      should "return 200" do
        assert_equal 200, last_response.status
      end

      should "generate a valid atom feed with a single entry" do
        assert_atom_feed_entries(1)
        assert_atom_feed_has_entry_for('You and Yours')
      end

      should "contain a service provider header" do
        assert_has_header "X-RadioTAG-Service-Provider", "BBC"
      end
    end
  end

  context "When the server supports unpaired tagging" do
    setup do
      TagServer.any_instance.stubs(:grants).returns({'unpaired' => GRANTS['unpaired'], 'can_register' => 'true'})
    end

    context "a POST to /tag" do
      context "with an invalid token" do
        setup do
          mock_auth("/authorized", {:token => "INVALID"}, 401)

          post '/tag',
          {
            :station=>"0.c224.ce15.ce1.dab",
            :time => Time.now.utc.to_i
          },
          { 'HTTP_X_RADIOTAG_AUTH_TOKEN' => 'INVALID' }
        end

        should "return 401 and unpaired grant" do
          assert_equal 401, last_response.status
          assert_has_grant_headers('unpaired')
        end

        should "contain a service provider header" do
          assert_has_header "X-RadioTAG-Service-Provider", "BBC"
        end
      end

      context "with a valid token" do
        setup do
          mock_auth("/authorized", {:token => "VALID"}, 200, {:token => "HNGZ" }.to_json)
          mock_auth("/auth", { :params => {:token => "VALID"} }, 200, {:token => "HNGZ"}.to_json, :get)
          Solr.expects(:solr_host).at_least_once.returns("solr.example.com")

          FakeWeb.register_uri(:get, %r|http://solr\.example\.com/solr/select.*|,
                               :body => File.read(File.dirname(__FILE__) + '/solr_response.json'))

          post '/tag',
          {
            :station=>"0.c224.ce15.ce1.dab", :time => Time.now.utc.to_i,
          },
          { 'HTTP_X_RADIOTAG_AUTH_TOKEN' => 'VALID' }
        end

        should "return 201" do
          assert_status 201
        end

        should "return a can-register grant" do
          assert_has_grant_headers('can_register')
        end

        should "generate a valid atom feed with a single entry" do
          assert_atom_feed_entries(1)
          assert_atom_feed_has_entry_for('You and Yours')
        end

        should "contain a service provider header" do
          assert_has_header "X-RadioTAG-Service-Provider", "BBC"
        end
      end
    end
  end

  context "When the server supports paired tagging" do
    setup do
      TagServer.any_instance.stubs(:grants).returns({'unpaired' => 'UNP1', 'can_register' => 'REG1'})
    end

    context "a POST to /tag" do
      context "with an invalid token" do
        setup do
          mock_auth("/authorized", {:token => "INVALID"}, 401)

          post '/tag',
          {
            :station=>"0.c224.ce15.ce1.dab",
            :time => Time.now.utc.to_i
          },
          { 'HTTP_X_RADIOTAG_AUTH_TOKEN' => 'INVALID' }
        end

        should "return 401" do
          assert_status 401
        end

        should "contain a service provider header" do
          assert_has_header "X-RadioTAG-Service-Provider", "BBC"
        end
      end

      context "with a valid token" do
        setup do
          mock_auth("/authorized", {:token => "VALID"}, 200, {:token => "HNGZ" }.to_json)
          mock_auth("/auth", { :params => {:token => "VALID"} }, 200, {:token => "HNGZ", :value => {:account_name => "alice", :account_id => "42"}}.to_json, :get)
          Solr.expects(:solr_host).at_least_once.returns("solr.example.com")

          FakeWeb.register_uri(:get, %r|http://solr\.example\.com/solr/select.*|,
                               :body => File.read(File.dirname(__FILE__) + '/solr_response.json'))

          post '/tag',
          {
            :station=>"0.c224.ce15.ce1.dab",
            :time => Time.now.utc.to_i
          },
          { 'HTTP_X_RADIOTAG_AUTH_TOKEN' => 'VALID' }
        end

        should "return 201 and no grants" do
          assert_status 201
          assert_has_no_grant_headers
        end

        should "contain an account_name header" do
          assert_has_header "X-RadioTAG-Account-Name", "alice"
        end

        should "contain an auth token header" do
          assert_has_header "X-RadioTAG-Auth-Token", "VALID"
        end

        should "generate a valid atom feed with a single entry" do
          assert_atom_feed_entries(1)
          assert_atom_feed_has_entry_for('You and Yours')
        end

        should "contain a service provider header" do
          assert_has_header "X-RadioTAG-Service-Provider", "BBC"
        end
      end
    end
  end

  context "When the server supports paired but not unpaired tagging" do
    setup do
      TagServer.any_instance.stubs(:grants).returns({'can_register' => 'REG1'})
    end

    context "a POST to /tag" do
      context "with an invalid token" do
        setup do
          mock_auth("/authorized", {:token => "INVALID"}, 401)

          Solr.expects(:solr_host).at_least_once.returns("solr.example.com")

          FakeWeb.register_uri(:get, %r|http://solr\.example\.com/solr/select.*|,
                               :body => File.read(File.dirname(__FILE__) + '/solr_response.json'))

          post '/tag',
          {
            :station=>"0.c224.ce15.ce1.dab", :time => Time.now.utc.to_i,
          },
          { 'HTTP_X_RADIOTAG_AUTH_TOKEN' => 'INVALID' }
        end

        should "return 200" do
          assert_status 200
          assert_has_grant_headers "can_register"
        end

        should "generate a valid atom feed with a single entry" do
          assert_atom_feed_entries(1)
          assert_atom_feed_has_entry_for('You and Yours')
        end

        should "contain a service provider header" do
          assert_has_header "X-RadioTAG-Service-Provider", "BBC"
        end
      end

      context "with a valid token" do
        setup do
          mock_auth("/authorized", {:token => "VALID"}, 200, {:token => "HNGZ" }.to_json)
          mock_auth("/auth", { :params => {:token => "VALID"} }, 200, {:token => "HNGZ", :value => {:account_name => "alice", :account_id => "42"}}.to_json, :get)

          Solr.expects(:solr_host).at_least_once.returns("solr.example.com")

          FakeWeb.register_uri(:get, %r|http://solr\.example\.com/solr/select.*|,
                               :body => File.read(File.dirname(__FILE__) + '/solr_response.json'))

          post '/tag',
          {
            :station=>"0.c224.ce15.ce1.dab",
            :time => Time.now.utc.to_i
          },
          { 'HTTP_X_RADIOTAG_AUTH_TOKEN' => 'VALID' }
        end

        should "return 201 and no grants" do
          assert_status 201
          assert_has_no_grant_headers
        end

        should "contain an account_name header" do
          assert_has_header "X-RadioTAG-Account-Name", "alice"
        end

        should "contain an auth token header" do
          assert_has_header "X-RadioTAG-Auth-Token", "VALID"
        end

        should "generate a valid atom feed with a single entry" do
          assert_atom_feed_entries(1)
          assert_atom_feed_has_entry_for('You and Yours')
        end

        should "contain a service provider header" do
          assert_has_header "X-RadioTAG-Service-Provider", "BBC"
        end
      end
    end
  end

  context "A POST to /token" do
    setup do
      TagServer.any_instance.stubs(:grants).returns(GRANTS)
    end

    context "without a grant" do
      setup do
        post '/token'
      end

      should "return 401" do
        assert_equal 401, last_response.status
      end

      should "contain a service provider header" do
        assert_has_header "X-RadioTAG-Service-Provider", "BBC"
      end
    end

    context "with an incorrect grant" do
      setup do
        post '/token', { :grant_scope => 'unpaired', :grant_token => "INVALID" }
      end

      should "return 401" do
        assert_equal 401, last_response.status
      end

      should "contain a service provider header" do
        assert_has_header "X-RadioTAG-Service-Provider", "BBC"
      end
    end

    context "with a correct grant" do
      setup do
        mock_auth("/auth", {:grant => { :scope => 'unpaired', :token => GRANTS['unpaired']}}, 204, '{"token":"XYZ"}')
        post '/token', { :grant_scope => 'unpaired', :grant_token => GRANTS['unpaired']}
      end

      should "return 204" do
        assert_equal 204, last_response.status
      end

      should "return a token" do
        assert_has_header 'X-RadioTAG-Auth-Token'
      end

      should "contain a service provider header" do
        assert_has_header "X-RadioTAG-Service-Provider", "BBC"
      end
    end
  end

  context "A POST to /registration_key" do
    context "with a valid can_register grant" do
      setup do
        mock_auth("/authorized", {:grant => { :scope => 'can_register', :token => GRANTS['can_register']}}, 200)
        post '/registration_key', { :grant_scope => 'can_register', :grant_token => GRANTS['can_register'] }
      end

      should "return 204" do
        assert_status 204
      end

      should "return a registration_key" do
        assert_has_header('X-RadioTAG-registration-key')
      end

      should "return a url for the Web Front End" do
        assert_has_header('X-RadioTAG-registration-url')
      end

      should "contain a service provider header" do
        assert_has_header "X-RadioTAG-Service-Provider", "BBC"
      end
    end

    context "with an invalid can_register grant" do
      setup do
        mock_auth("/authorized", {:grant => { :scope => 'can_register', :token => GRANTS['can_register']}}, 401)
        post '/registration_key', { :grant_scope => 'can_register', :grant_token => GRANTS['can_register']}
      end

      should "return 401" do
        assert_status 401
      end

      should "not return a registration_key" do
        assert_has_no_header('X-RadioTAG-registration-key')
      end

      should "not return a url for the Web Front End" do
        assert_has_no_header('X-RadioTAG-registration-url')
      end

      should "contain a service provider header" do
        assert_has_header "X-RadioTAG-Service-Provider", "BBC"
      end
    end
  end

  context "A POST to /register" do
    context "with valid parameters" do
      setup do
        mock_resource = mock()
        ::AuthService.expects(:[]).twice.with("/auth").returns(mock_resource)

        mock_response1 = stub(:code => 200,
                              :body => {
                                :token => "NEW_TOKEN"
                              }.to_json)

        mock_resource.expects(:post).with(
                                          {
                                            :registration_key => "VALID_KEY",
                                            :pin => "VALID_PIN",
                                          }).returns(mock_response1)

        mock_response2 = stub(:code => 200,
                              :body => {
                                :value => {
                                  :account_id => "42",
                                  :account_name => "alice"
                                }
                              }.to_json)

        mock_resource.expects(:get).with(
                                         {
                                           :params => { :token => "NEW_TOKEN" }
                                         }).returns(mock_response2)

        post('/register',
             {:registration_key => 'VALID_KEY',
               :pin => 'VALID_PIN'
             },
             { 'HTTP_X_RADIOTAG_AUTH_TOKEN' => 'VALID_TOKEN' }
             )
      end

      should "return 201" do
        assert_status(201)
      end

      should "return an account name" do
        assert_has_header('X-RadioTAG-account-name', "alice")
      end

      should "return a token" do
        assert_has_header('X-RadioTAG-Auth-Token', 'NEW_TOKEN')
      end

      should "contain a service provider header" do
        assert_has_header "X-RadioTAG-Service-Provider", "BBC"
      end
    end

    context "with invalid parameters" do
      setup do
        mock_auth("/auth",
                  {:registration_key => "INVALID_KEY", :pin => "INVALID_PIN"},
                  401, '')

        post('/register',
             {
               :registration_key => 'INVALID_KEY',
               :pin => 'INVALID_PIN',
             },
             { 'HTTP_X_RADIOTAG_AUTH_TOKEN' => 'INVALID_TOKEN' }
             )
      end

      should "return 401" do
        assert_status(401)
      end

      should "not return an account id" do
        assert_has_no_header('X-RadioTAG-account-id')
      end

      should "not return a token" do
        assert_has_no_header('X-RadioTAG-Auth-Token')
      end

      should "contain a service provider header" do
        assert_has_header "X-RadioTAG-Service-Provider", "BBC"
      end
    end
  end

  context "A GET to /tags" do
    setup do
      Device.all.destroy
    end

    context "with no token" do
      should "return 401" do
        get '/tags'
        assert_equal 401, last_response.status
        assert_has_header "X-RadioTAG-Service-Provider", "BBC"
      end

    end

    context "for an unpaired account" do
      context "with a valid token" do
        setup do
          Device.all.destroy
          mock_auth("/authorized", {:token => "TAGTOK"}, 204, '{}')
          mock_auth("/auth", { :params => {:token => "TAGTOK"}}, 204, '{}', :get)
        end

        context "when no tags have been stored for this device" do
          setup do
            device = Device.first_or_create(:token => "TAGTOK")
            device.tags = []
            device.save
            get '/tags', '', { 'HTTP_X_RADIOTAG_AUTH_TOKEN' => 'TAGTOK' }
          end

          should "return 200" do
            assert_equal 200, last_response.status
          end

          should "generate a valid atom feed with no entries" do
            assert_atom_feed_entries(0)
          end

          should "return a can-register grant" do
            assert_has_grant_headers('can_register')
          end

          should "contain a service provider header" do
            assert_has_header "X-RadioTAG-Service-Provider", "BBC"
          end
        end

        context "when tags have been stored for this device" do
          setup do
            device = Device.first_or_create(:token => "TAGTOK")
            device.tags.destroy

            @old_tag = Tag.new(:time => Time.now.utc.to_i - 3600, :station => "0.c224.ce15.ce1.dab")
            @new_tag = Tag.new(:time => Time.now.utc.to_i, :station => "0.c224.ce15.ce1.dab")

            device.tags = [@old_tag, @new_tag]
            device.save

            Solr.expects(:solr_host).at_least_once.returns("solr.example.com")

            FakeWeb.register_uri(:get, %r|http://solr\.example\.com/solr/select.*|,
                                 :body => File.read(File.dirname(__FILE__) + '/solr_response.json'))

            get '/tags', '', { 'HTTP_X_RADIOTAG_AUTH_TOKEN' => 'TAGTOK' }
          end

          should "return 200" do
            assert_equal 200, last_response.status
          end

          should "generate a valid atom feed with 2 entries" do
            assert_atom_feed_entries(2)
            assert_atom_feed_has_entry_for('You and Yours')
          end

          should "sort the entries in date order" do
            doc = Nokogiri::XML(last_response.body)
            assert_equal 0, doc.errors.size
            assert_equal "urn:uuid:#{@new_tag.uuid}", doc.xpath('//xmlns:entry/xmlns:id').first.content
          end

          should "return a can-register grant" do
            assert_has_grant_headers('can_register')
          end

          should "contain a service provider header" do
            assert_has_header "X-RadioTAG-Service-Provider", "BBC"
          end
        end
      end
    end

    context "for a paired account" do
      context "with a valid token" do
        setup do
          User.all.destroy
          user_data = {
            :name => "bob"
          }

          user = User.create(user_data)
          Device.all.destroy
          mock_auth("/authorized", {:token => "USERTAGTOK"}, 204, { :id => user.id }.to_json)
          mock_auth("/auth", { :params => {:token => "USERTAGTOK"}}, 204, { :value => { :account_id => user.id, :account_name => user.name }}.to_json, :get)
          @device = Device.first_or_create(:token => "NOTUSED", :user => user)
          @device.tags.destroy
        end

        context "when no tags have been stored for this user" do
          setup do
            get '/tags', { }, { 'HTTP_X_RADIOTAG_AUTH_TOKEN' => 'USERTAGTOK' }
          end

          should "return 200" do
            assert_equal 200, last_response.status
          end

          should "generate a valid atom feed with no entries" do
            doc = Nokogiri::XML(last_response.body)
            assert_atom_feed_entries(0)
          end

          should "contain an account_name header" do
            assert_has_header "X-RadioTAG-Account-Name", "bob"
          end

          should "contain an auth token header" do
            assert_has_header "X-RadioTAG-Auth-Token", "USERTAGTOK"
          end

          should "contain a service provider header" do
            assert_has_header "X-RadioTAG-Service-Provider", "BBC"
          end
        end

        context "when tags have been stored for this user" do
          setup do
            @old_tag = Tag.new(:time => Time.now.utc.to_i - 3600, :station => "0.c224.ce15.ce1.dab")
            @new_tag = Tag.new(:time => Time.now.utc.to_i, :station => "0.c224.ce15.ce1.dab")

            @device.tags = [@old_tag, @new_tag]
            @device.save

            Solr.expects(:solr_host).at_least_once.returns("solr.example.com")

            FakeWeb.register_uri(:get, %r|http://solr\.example\.com/solr/select.*|,
                                 :body => File.read(File.dirname(__FILE__) + '/solr_response.json'))

            get '/tags', '', { 'HTTP_X_RADIOTAG_AUTH_TOKEN' => 'USERTAGTOK' }
          end

          should "return 200" do
            assert_equal 200, last_response.status
          end

          should "generate a valid atom feed with 2 entries" do
            assert_atom_feed_entries(2)
            assert_atom_feed_has_entry_for('You and Yours')
          end

          should "sort the entries in date order" do
            doc = Nokogiri::XML(last_response.body)
            assert_equal 0, doc.errors.size
            assert_equal "urn:uuid:#{@new_tag.uuid}", doc.xpath('//xmlns:entry/xmlns:id').first.content
          end

          should "contain an account_name header" do
            assert_has_header "X-RadioTAG-Account-Name", "bob"
          end

          should "contain an auth token header" do
            assert_has_header "X-RadioTAG-Auth-Token", "USERTAGTOK"
          end

          should "contain a service provider header" do
            assert_has_header "X-RadioTAG-Service-Provider", "BBC"
          end
        end
      end
    end
  end
end
