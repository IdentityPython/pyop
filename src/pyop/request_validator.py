import logging

from oic.exception import MessageException
from oic.oic import PREFERENCE2PROVIDER

from .exceptions import InvalidClientRegistrationRequest, InvalidAuthenticationRequest
from .util import is_allowed_response_type, find_common_values

logger = logging.getLogger(__name__)


def authorization_request_verify(authentication_request):
    """
    Verifies that all required parameters and correct values are included in the authentication request.
    :param authentication_request: the authentication request to verify
    :raise InvalidAuthenticationRequest: if the authentication is incorrect
    """
    try:
        authentication_request.verify()
    except MessageException as e:
        raise InvalidAuthenticationRequest(str(e), authentication_request, oauth_error='invalid_request') from e


def client_id_is_known(provider, authentication_request):
    """
    Verifies the client identifier is known.
    :param provider: provider instance
    :param authentication_request: the authentication request to verify
    :raise InvalidAuthenticationRequest: if the client_id is unknown
    """
    if authentication_request['client_id'] not in provider.clients:
        raise InvalidAuthenticationRequest('Unknown client_id \'{}\''.format(authentication_request['client_id']),
                                           authentication_request,
                                           oauth_error='unauthorized_client')


def redirect_uri_is_in_registered_redirect_uris(provider, authentication_request):
    """
    Verifies the redirect uri is registered for the client making the request.
    :param provider: provider instance
    :param authentication_request: authentication request to verify
    :raise InvalidAuthenticationRequest: if the redirect uri is not registered
    """
    error = InvalidAuthenticationRequest('Redirect uri \'{}\' is not registered'.format(
        authentication_request['redirect_uri']), authentication_request)
    try:
        allowed_redirect_uris = provider.clients[authentication_request['client_id']]['redirect_uris']
    except KeyError as e:
        logger.error('client metadata is missing redirect_uris')
        raise error

    if authentication_request['redirect_uri'] not in allowed_redirect_uris:
        raise error


def response_type_is_in_registered_response_types(provider, authentication_request):
    """
    Verifies that the requested response type is allowed for the client making the request.
    :param provider: provider instance
    :param authentication_request: authentication request to verify
    :raise InvalidAuthenticationRequest: if the response type is not allowed
    """
    error = InvalidAuthenticationRequest('Response type \'{}\' is not registered'.format(
        ' '.join(authentication_request['response_type'])),
        authentication_request, oauth_error='invalid_request')
    try:
        allowed_response_types = provider.clients[authentication_request['client_id']]['response_types']
    except KeyError as e:
        logger.error('client metadata is missing response_types')
        raise error

    if not is_allowed_response_type(authentication_request['response_type'], allowed_response_types):
        raise error


def userinfo_claims_only_specified_when_access_token_is_issued(authentication_request):
    """
    According to <a href="http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter">
    "OpenID Connect Core 1.0", Section 5.5</a>: "When the userinfo member is used, the request MUST
    also use a response_type value that results in an Access Token being issued to the Client for
    use at the UserInfo Endpoint."
    :param authentication_request: the authentication request to verify
    :raise InvalidAuthenticationRequest: if the requested claims can not be returned according to the request
    """
    will_issue_access_token = authentication_request['response_type'] != ['id_token']
    contains_userinfo_claims_request = 'claims' in authentication_request and 'userinfo' in authentication_request[
        'claims']
    if not will_issue_access_token and contains_userinfo_claims_request:
        raise InvalidAuthenticationRequest('Userinfo claims cannot be requested, when response_type=\'id_token\'',
                                           authentication_request,
                                           oauth_error='invalid_request')


def requested_scope_is_supported(provider, authentication_request):
    requested_scopes = set(authentication_request['scope'])
    supported_scopes = set(provider.provider_configuration['scopes_supported'])
    requested_unsupported_scopes = requested_scopes - supported_scopes
    if requested_unsupported_scopes:
        logger.warning('Request contains unsupported/unknown scopes: {}'
                                           .format(', '.join(requested_unsupported_scopes)))


def registration_request_verify(registration_request):
    """
    Verifies that all required parameters and correct values are included in the client registration request.
    :param registration_request: the authentication request to verify
    :raise InvalidClientRegistrationRequest: if the registration is incorrect
    """
    try:
        registration_request.verify()
    except MessageException as e:
        raise InvalidClientRegistrationRequest(str(e), registration_request, oauth_error='invalid_request') from e


def client_preferences_match_provider_capabilities(provider, registration_request):
    """
    Verifies that all requested preferences in the client metadata can be fulfilled by this provider.
    :param registration_request: the authentication request to verify
    :raise InvalidClientRegistrationRequest: if the registration is incorrect
    """

    def match(client_preference, provider_capability):
        if isinstance(client_preference, list):
            # deal with comparing space separated values, e.g. 'response_types', without considering the order
            # at least one requested preference must be matched
            return len(find_common_values(client_preference, provider_capability)) > 0

        return client_preference in provider_capability

    for client_preference in registration_request.keys():
        if client_preference not in PREFERENCE2PROVIDER:
            # metadata parameter that shouldn't be matched
            continue

        provider_capability = PREFERENCE2PROVIDER[client_preference]
        if not match(registration_request[client_preference], provider.configuration_information[provider_capability]):
            raise InvalidClientRegistrationRequest(
                'Could not match client preference {}={} with provider capability {}={}'.format(
                    client_preference, registration_request[client_preference], provider_capability,
                    provider.configuration_information[provider_capability]),
                registration_request,
                oauth_error='invalid_request')
