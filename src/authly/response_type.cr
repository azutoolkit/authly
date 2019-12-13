module Authly
  RESPONSE = {
    ResponseType::Code => TemporaryCode,
    # TODO: Implement ResponseType::IdToken => IdToken,
    ResponseType::Token => Implicit,
  }
  enum ResponseType
    Code
    IdToken
    Token
  end
end
