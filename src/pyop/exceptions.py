from oic.oic.message import AuthorizationErrorResponse, ClientRegistrationErrorResponse

from .util import should_fragment_encode


class OAuthError(ValueError):
    def __init__(self, message, oauth_error):
        super().__init__(message)
        self.oauth_error = oauth_error


class InvalidAuthorizationCode(OAuthError):
    def __init__(self, message):
        super().__init__(message, 'invalid_grant')


class InvalidRefreshToken(OAuthError):
    def __init__(self, message):
        super().__init__(message, 'invalid_grant')


class InvalidAccessToken(OAuthError):
    def __init__(self, message):
        super().__init__(message, 'invalid_token')


class InvalidScope(OAuthError):
    def __init__(self, message):
        super().__init__(message, 'invalid_scope')


class InvalidClientAuthentication(OAuthError):
    def __init__(self, message):
        super().__init__(message, 'invalid_client')


class InvalidSubjectIdentifier(ValueError):
    pass


class InvalidRequestError(OAuthError):
    def __init__(self, message, parsed_request, oauth_error):
        super().__init__(message, oauth_error)
        self.request = parsed_request


class InvalidAuthenticationRequest(InvalidRequestError):
    def __init__(self, message, parsed_request, oauth_error=None):
        super().__init__(message, parsed_request, oauth_error)

    def to_error_url(self):
        redirect_uri = self.request.get('redirect_uri')
        response_type = self.request.get('response_type')
        if redirect_uri and response_type and self.oauth_error:
            error_resp = AuthorizationErrorResponse(error=self.oauth_error, error_message=str(self),
                                                    state=self.request.get('state'))
            return error_resp.request(redirect_uri, should_fragment_encode(self.request))

        return None


class InvalidTokenRequest(InvalidRequestError):
    def __init__(self, message, parsed_request, oauth_error='invalid_request'):
        super().__init__(message, parsed_request, oauth_error)


class InvalidClientRegistrationRequest(InvalidRequestError):
    def __init__(self, message, parsed_request, oauth_error='invalid_request'):
        super().__init__(message, parsed_request, oauth_error)

    def to_json(self):
        error = ClientRegistrationErrorResponse(error=self.oauth_error, error_description=str(self))
        return error.to_json()


class BearerTokenError(ValueError):
    pass


class AuthorizationError(Exception):
    pass
