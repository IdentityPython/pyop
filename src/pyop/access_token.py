import logging
from urllib.parse import parse_qsl

from .exceptions import BearerTokenError

logger = logging.getLogger(__name__)


class AccessToken(object):
    """
    Representation of an access token.
    """
    BEARER_TOKEN_TYPE = 'Bearer'

    def __init__(self, value, expires_in, typ=BEARER_TOKEN_TYPE):
        self.value = value
        self.expires_in = expires_in
        self.type = typ


def extract_bearer_token_from_http_request(parsed_request=None, authz_header=None):
    # type (Optional[Mapping[str, str]], Optional[str] -> str
    """
    Extracts a Bearer token from an http request
    :param parsed_request: parsed request (URL query part of request body)
    :param authz_header: HTTP Authorization header
    :return: Bearer access token, if found
    :raise BearerTokenError: if no Bearer token could be extracted from the request
    """
    if authz_header:
        # Authorization Request Header Field: https://tools.ietf.org/html/rfc6750#section-2.1
        if authz_header.startswith(AccessToken.BEARER_TOKEN_TYPE):
            access_token = authz_header[len(AccessToken.BEARER_TOKEN_TYPE) + 1:]
            logger.debug('found access token %s in authz header', access_token)
            return access_token
    elif parsed_request:
        if 'access_token' in parsed_request:
            """
            Form-Encoded Body Parameter: https://tools.ietf.org/html/rfc6750#section-2.2, and
            URI Query Parameter: https://tools.ietf.org/html/rfc6750#section-2.3
            """
            access_token = parsed_request['access_token']
            logger.debug('found access token %s in request', access_token)
            return access_token

    raise BearerTokenError('Bearer Token could not be found in the request')
