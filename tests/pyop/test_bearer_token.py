from urllib.parse import urlencode

import pytest

from pyop.access_token import extract_bearer_token_from_http_request, BearerTokenError

ACCESS_TOKEN = 'abcdef'


class TestExtractBearerTokenFromHttpRequest(object):
    def test_authorization_header(self):
        http_headers = {'Authorization': 'Bearer {}'.format(ACCESS_TOKEN)}
        assert extract_bearer_token_from_http_request(http_headers=http_headers) == ACCESS_TOKEN

    def test_non_bearer_authorization_header(self):
        http_headers = {'Authorization': 'Basic {}'.format(ACCESS_TOKEN)}
        with pytest.raises(BearerTokenError):
            extract_bearer_token_from_http_request(http_headers=http_headers)

    def test_access_token_in_urlencoded_request(self):
        data = {
            'foo': 'bar',
            'access_token': ACCESS_TOKEN
        }
        assert extract_bearer_token_from_http_request(request=urlencode(data)) == ACCESS_TOKEN

    def test_urlencoded_request_without_access_token(self):
        data = {
            'foo': 'bar',
        }
        with pytest.raises(BearerTokenError):
            extract_bearer_token_from_http_request(request=urlencode(data))
