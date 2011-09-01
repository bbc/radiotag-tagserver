require 'json'
require 'time'

class TrialLogger
  def initialize(app)
    @app = app
  end
  def call(env)
    data = { }
    data["TIME"] = Time.now.utc.xmlschema
    keys = %w[HTTP_X_FORWARDED_FOR HTTP_USER_AGENT REQUEST_URI HTTP_X_RADIOTAG_AUTH_TOKEN REQUEST_METHOD]
    keys.each do |key|
      data[key] = env[key]
    end
    response = @app.call(env)
    data["HTTP_STATUS"] = response[0]
    headers = response[1]
    data["X-RadioTAG-Account-Name"] = headers["X-RadioTAG-Account-Name"]
    puts "RADIOTAG-TAG: " + data.to_json
    response
  end
end
