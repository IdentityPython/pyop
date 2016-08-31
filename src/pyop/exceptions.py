from oic.oauth2.message import ErrorResponse

from .util import should_fragment_encode


class BearerTokenError(ValueError):
    pass


class InvalidAuthorizationCode(ValueError):
    pass


class InvalidAccessToken(ValueError):
    pass


class InvalidRefreshToken(ValueError):
    pass


class InvalidSubjectIdentifier(ValueError):
    pass


class InvalidScope(ValueError):
    pass


class InvalidClientAuthentication(ValueError):
    pass


class InvalidAuthenticationRequest(ValueError):
    def __init__(self, message, parsed_request, oauth_error=None):
        super().__init__(message)
        self.request = parsed_request
        self.oauth_error = oauth_error

    def to_error_url(self):
        redirect_uri = self.request.get('redirect_uri')
        if redirect_uri and self.oauth_error:
            error_resp = ErrorResponse(error=self.oauth_error, error_message=str(self))
            return error_resp.request(redirect_uri, should_fragment_encode(self.request))

        return None


class AuthorizationError(Exception):
    pass


class InvalidTokenRequest(ValueError):
    def __init__(self, message, oauth_error='invalid_request'):
        super().__init__(message)
        self.oauth_error = oauth_error


class InvalidUserinfoRequest(ValueError):
    pass


class InvalidClientRegistrationRequest(ValueError):
    def __init__(self, message, oauth_error='invalid_request'):
        super().__init__(message)
        self.oauth_error = oauth_error
