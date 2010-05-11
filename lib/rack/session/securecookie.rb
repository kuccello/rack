require 'openssl'
require 'rack/request'
require 'rack/response'

# Kristan "Krispy" Uccello - May 10, 2010
#
# This middleware is a replacement for the Rack::Session::Cookie class in a rack application
# It has been desinged to add some security to the session cookie by way of tokenizing the information
# known about a visitor's browser and point of origin (IP address).
#
# Here is how it works:
# On the first request from a client (Browser) a session will be created normally (as in the same
# way a session is created using Rack::Session::Cookie). On each request there after where the client
# is still within the session timeout window, SecureCookie looks for the :secure_client_token which
# was created on the first request when the cookie was created. The :secure_client_token is a hash
# of the client's IP, User-Agent and session id ('rack.session' value or @key value). The :secure_client_token
# is then compared against the session_data value for the key :secure_token (again, generated when
# the session is first created and stored in the newly created session) if these two values do not
# match then the session is invalidated and a new session is created.
#
# The :secure_client_token value will be updated on each request via a step wise counter
#
# Why did I create this?
# ----------------------
# I was having a discussion with a coworker and he was insistant that sessions and cookies were insecure by
# nature. To which I claimed ignorance so I went out to research the issue and came across this
# article: http://www.technicalinfo.net/papers/WebBasedSessionManagement.html which got me thinking
# about how I might inject a little trust into my cookie/session without exposing the security issues
# that exist in cookie token based session pools. I wanted to try to prevent the possibility of
# someone swiping a cookie value and being able to use it to access a clients account for which
# they are not the owner. All I have done here is made is harder to accomplish this. Now the "attacker"
# would need to "spoof" the IP and user agent within a request frame of a logged in user request.
#
#
module Rack
  module Session
    class SecureCookie

      def initialize(app, options={})
        @app = app
        @key = options[:key] || "rack.session"
        @secret = options[:secret]
        @default_options = {:domain => nil,
          :path => "/",
          :expire_after => nil}.merge(options)
      end

      def call(env)
        load_session(env)
        status, headers, body = @app.call(env)
        commit_session(env, status, headers, body)
      end

      private

      def load_session(env)
        request = Rack::Request.new(env)

        session_data = request.cookies[@key]

        if @secret && session_data
          session_data, digest = session_data.split("--")
          session_data = nil  unless digest == generate_hmac(session_data)
        end

        begin
          session_data = session_data.unpack("m*").first
          session_data = Marshal.load(session_data)


          time_stamp = Time.new.to_i
          secure_client_ticket = session_data[:secure_client_ticket] || time_stamp
          session_data[:secure_client_ticket] = secure_client_ticket + 1 # make sure it has a value

          ip = request.ip
          user_agent = env['HTTP_USER_AGENT']
          data = "#{secure_client_ticket}#{ip}#{user_agent}#{@key}"
          new_data = "#{secure_client_ticket + 1}#{ip}#{user_agent}#{@key}"
          secure_token = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, @secret || 'soc.hash', data)
          new_secure_token = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, @secret || 'soc.hash', new_data)

          secure_client_token = session_data[:secure_client_token] # Token Value - Unique per visitor (won't be unique for different tabs in the same browser)
          if secure_client_token then
            if secure_token == secure_client_token then
              session_data[:secure_client_token] = new_secure_token
              env["rack.session"] = session_data
            else
              env["rack.session"] = {:secure_client_token => new_secure_token}
            end
          else
            # Not a secure session yet
            session_data[:secure_client_token] = new_secure_token # now it has the new security token it needs
            env["rack.session"] = session_data
          end
        rescue
          env["rack.session"] = {:secure_client_token => new_secure_token}
        end

        env["rack.session.options"] = @default_options.dup
      end

      def commit_session(env, status, headers, body)
        session_data = Marshal.dump(env["rack.session"])
        session_data = [session_data].pack("m*")

        if @secret
          session_data = "#{session_data}--#{generate_hmac(session_data)}"
        end

        if session_data.size > (4096 - @key.size)
          env["rack.errors"].puts("Warning! Rack::Session::Cookie data size exceeds 4K. Content dropped.")
        else
          options = env["rack.session.options"]
          cookie = Hash.new
          cookie[:value] = session_data
          cookie[:expires] = Time.now + options[:expire_after] unless options[:expire_after].nil?
          Rack::Utils.set_cookie_header!(headers, @key, cookie.merge(options))
        end

        [status, headers, body]
      end

      def generate_hmac(data)
        OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, @secret, data)
      end

    end
  end
end
