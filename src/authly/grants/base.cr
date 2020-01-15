module Grants
  abstract class Base
    getter client_id : String,
      client_secret : String,
      redirect_uri : URI,
      scope : String

    abstract def authorize! : AccessToken
  end
end
