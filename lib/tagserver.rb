require 'bbc_service_map'

class TagServer < Sinatra::Base
  def logger
    @logger ||= Logger.new(env['rack.errors'])
    @logger.progname = File.basename(__FILE__)
    @logger
  end

  def grants
    GRANTS
  end

  helpers do
    def check_grant(grant)
      params['grant_scope'] == grant and params['grant_token'] == grants[grant]
    end

    def get_token
      token = env['HTTP_X_RADIOTAG_AUTH_TOKEN']
      if token.to_s.strip.empty?
        nil
      else
        token
      end
    end

    def extract_request_params(request)
      tag = {
        "station" => params['station'],
        "time"    => params['time']
      }
      [get_token, tag]
    end

    def grant_header(scope)
      headers({
                'X-Radiotag-Grant-Scope' => scope,
                'X-Radiotag-Grant-Token' => grants[scope]
              })
    end

    def service_provider_header
      headers({
                'X-Radiotag-Service-Provider' => 'BBC'
              })
    end

    def get_account_data(token)
      response = AuthService["/auth"].get({:params => { :token => token }}) { |response, request, reply| response }
      case response.code
      when 200..299
        data = JSON.parse(response.body)
        data["value"]
      else
        nil
      end
    end

    def add_account_headers(token, account_name)
      headers(
              "X-Radiotag-Auth-Token" => token,
              "X-Radiotag-Account-Name" => account_name
              )
    end

  end

  before do
    service_provider_header
  end

  get '/' do
    "Tag server"
  end

  post '/registration_key' do
    if check_grant('can_register')
      response = AuthService["/authorized"].post({:grant =>
                                                   { :scope => 'can_register',
                                                     :token => grants['can_register']
                                                   }
                                                 }
                                                 ) { |response, request, reply| response }
      case response.code
      when 200
        headers(
                'X-Radiotag-Registration-Key' => GenerateID.rand_hex,
                'X-Radiotag-Registration-Url' => "http://radiotag.prototype0.net/"
                )
        status 204
      else
        status 401
      end
    else
      status 401
    end
  end

  post '/tag' do
    token, tag_data = extract_request_params(request)

    if BBCRD::ServiceMap.lookup(tag_data['station']).nil?
      halt 400, "Invalid station identifier: '#{tag_data['station']}'"
    end

    tag  = Tag.new(:station   => tag_data['station'],
                   :time      => tag_data['time'])

    halt 400, "Invalid params" if !tag.valid?

    begin
      response = AuthService["/authorized"].post({:token=> token.to_s}) { |response, request, reply| response }

      case response.code
      when 400..499
        if grants['unpaired']
          grant_header 'unpaired'
          halt 401, "Must request token"
        else
          if grants['can_register']
            grant_header 'can_register'
          end
          status 200
          nokogiri :tag, :locals => {:tag => tag}
        end
      when 200..299
        has_account = false
        response2 = AuthService["/auth"].get({ :params => {:token=> token.to_s}}) { |response, request, reply| response }
        case response2.code
        when 200..299
          data = JSON.parse(response2.body)
          if data["value"] and data["value"]["account_id"]
            logger.info "Account: #{data["value"]}"
            add_account_headers(token, data['value']['account_name'])
            has_account = true
          end
        when 400...499
          if grants['unpaired']
            grant_header 'unpaired'
          end
          halt 401, "Authentication failed"
        else
          logger.error "Unknown error while authenticating: #{response2.code} - #{response2.body.inspect}"
          halt response2.code, "Unknown error while authenticating"
        end

        device = Device.first_or_create(:token => data["token"])
        device.tags << tag

        if tag.save
          device.save

          if grants['can_register'] and !has_account
            logger.info "Added can_register grant"
            grant_header 'can_register'
          end

          status 201
          nokogiri :tag, :locals => {:tag => tag}
        else
          logger.error "Could not create tag (#{tag.errors.inspect})"
          halt 400, "Could not create tag (#{tag.errors.inspect})"
        end
      else
        raise RuntimeError, "Unhandled response code #{response.code} from authorization server"
      end
    rescue => e
      logger.error "Internal server error: #{e}"
      halt 500, "Internal server error"
    end
  end

  def dbg(*a)
    #STDERR.puts a.inspect
  end

  get '/tags' do
    dbg [:tags, 1]
    if token = get_token
      begin
        dbg [:tags, 2]
        response = AuthService["/authorized"].post({:token => token}) { |response, request, reply| response }
        case response.code
        when 200..299
          dbg [:tags, 3]
          data = get_account_data(token)
          if data and id = data["account_id"]
            dbg [:tags, 4]
            # this is a paired user account
            user = User.first(:id => id)
            tags = user.tags(:order => :time.desc)
            add_account_headers(token, data['account_name'])
          else
            dbg [:tags, 5]
            # this is an unpaired device account
            device = Device.first(:token => token)
            if device.nil?
              dbg [:tags, 6]
              halt 401, "Unauthorized: No device for token #{token}"
            else
              dbg [:tags, 7]
              tags = device.tags(:order => :time.desc)
            end
            if grants['can_register']
              dbg [:tags, 8]
              grant_header 'can_register'
            end
          end
          dbg [:tags, 9]
          nokogiri :tags, :locals => {:tags => tags}
        else
          dbg [:tags, 10]
          logger.error "Call to AuthService /authorized returned #{response.code}: #{response.inspect}"
          halt 401, "Authentication failed"
        end
      rescue => e
        dbg [:tags, 11]
        halt 500, "Internal server error #{e}"
      end
    else # token
      dbg [:tags, 12]
      halt 401, "Unauthorized"
    end
  end

  post '/register' do
    registration_key = params[:registration_key] or halt 400
    pin = params[:pin] or halt 400
    token = get_token

    response = AuthService["/auth"].post({
                                           :registration_key => registration_key,
                                           :pin => pin
                                         }) { |response, request, reply| response }

    case response.code
    when 200..299
      auth_data = JSON.parse(response.body)
      new_token = auth_data['token']

      get_response = AuthService["/auth"].get({:params => { :token => new_token }}) { |response, request, reply| response }
      case get_response.code
      when 200..299
        data = JSON.parse(get_response.body)
        user_id = data['value']['account_id'].to_i

        # FIXME: validate this
        # if anon to paired, then no Device
        # if unpaired to paired, then we expect Device to exist
        if device = Device.first(:token => token)
          user = User.first(:id => user_id)
          device.user = user
          device.token = new_token
          device.save!
        end
        add_account_headers(new_token, data['value']['account_name'])
        status 201
      else
        halt 500
      end
    when 400..499
      halt 401
    else
      halt response.code
    end
  end

  post '/token' do
    if check_grant('unpaired')
      response = AuthService["/auth"].post({:grant =>
                                             {
                                               :scope => 'unpaired',
                                               :token => grants['unpaired']
                                             }
                                           }
                                           ) { |response, request, reply| response }
      case response.code
      when 200..299
        data = JSON.parse(response.body)
        headers 'X-radiotag-auth-token' => data["token"]
        status 204
      when 400..499
        status 403
      else
        status 500
      end
    else
      status 401
    end
  end
end
