require 'rack/protection'

module Rack
  module Protection
    ##
    # Prevented attack::   CSRF
    # Supported browsers:: all
    # More infos::         http://flask.pocoo.org/docs/security/#json-security
    #
    # JSON GET APIs are vulnerable to being embedded as JavaScript while the
    # Array prototype has been patched to track data. Checks the HTTP origin
    # even on GET requests if the content type is JSON.
    class JsonCsrf < Base
      default_reaction :deny

      def call(env)
        status, headers, body = app.call(env)
        http_access_control_allow_origin = headers['Access-Control-Allow-Origin']
        http_origin = env['HTTP_ORIGIN']
        origin_allowed = true
        if http_origin && http_access_control_allow_origin
          if http_access_control_allow_origin != '*' &&
               URI(http_access_control_allow_origin).host != URI(http_origin).host
            origin_allowed = false
          end
        end
        if http_origin != Request.new(env).host && !origin_allowed
          result = react(env)
          warn env, "attack prevented by #{self.class}"
        end
        result or [status, headers, body]
      end
    end
  end
end
