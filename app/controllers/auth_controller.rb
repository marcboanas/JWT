class AuthController < ApplicationController
  skip_before_action :authenticate_request
  def authenticate
    user = User.where(:email => params[:email]).first

    if user
      if User.authenticate(params[:email], params[:password])
        render json: { auth_token: user.generate_auth_token }
      else
        render_error_message(401, "Wrong Password")
      end
    else
      render_error_message(400, "No User found by this email ID")
    end
  end
end
