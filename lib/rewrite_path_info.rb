class RewritePathInfo
  def initialize(app)
    @app = app
  end
  def call(env)
    if env["PATH_INFO"] == "" && env["SCRIPT_NAME"] != ""
      # p [:rewriting, env["PATH_INFO"], :to, env["SCRIPT_NAME"]]
      env["PATH_INFO"] = env["SCRIPT_NAME"]
    end
    response = @app.call(env)
    response
  end
end

