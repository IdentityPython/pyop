import base64
import logging

from .exceptions import InvalidClientAuthentication

logger = logging.getLogger(__name__)


def verify_client_authentication(clients, parsed_request, authz_header=None):
    # type: (Mapping[str, str], Mapping[str, Mapping[str, Any]], Optional[str]) -> bool
    """
    Verifies client authentication at the token endpoint, see
    <a href="https://tools.ietf.org/html/rfc6749#section-2.3.1">"The OAuth 2.0 Authorization Framework",
    Section 2.3.1</a>
    :param parsed_request: key-value pairs from parsed urlencoded request
    :param clients: clients db
    :param authz_header: the HTTP Authorization header value
    :return: the unmodified parsed request
    :raise InvalidClientAuthentication: if the client authentication was incorrect
    """
    client_id = None
    client_secret = None
    authn_method = None
    if authz_header:
        logger.debug('client authentication in Authorization header %s', authz_header)

        authz_scheme = authz_header.split(maxsplit=1)[0]
        if authz_scheme == 'Basic':
            authn_method = 'client_secret_basic'
            credentials = authz_header[len('Basic '):]
            missing_padding = 4 - len(credentials) % 4
            if missing_padding:
                credentials += '=' * missing_padding
            try:
                auth = base64.urlsafe_b64decode(credentials.encode('utf-8')).decode('utf-8')
            except UnicodeDecodeError as e:
                raise InvalidClientAuthentication('Could not userid/password from authorization header'.format(authz_scheme))
            client_id, client_secret = auth.split(':')
        else:
            raise InvalidClientAuthentication('Unknown scheme in authorization header, {} != Basic'.format(authz_scheme))
    elif 'client_id' in parsed_request:
        logger.debug('client authentication in request body %s', parsed_request)

        client_id = parsed_request['client_id']
        if 'client_secret' in parsed_request:
            authn_method = 'client_secret_post'
            client_secret = parsed_request['client_secret']
        else:
            authn_method = 'none'
            client_secret = None

    if client_id not in clients:
        raise InvalidClientAuthentication('client_id \'{}\' unknown'.format(client_id))

    client_info = clients[client_id]
    if client_secret != client_info.get('client_secret', None):
        raise InvalidClientAuthentication('Incorrect client_secret')

    expected_authn_method = client_info.get('token_endpoint_auth_method', 'client_secret_basic')
    if authn_method != expected_authn_method:
        raise InvalidClientAuthentication(
            'Wrong authentication method used, MUST use \'{}\''.format(expected_authn_method))

    return client_id
