import pytest

from pyop.access_token import extract_bearer_token_from_http_request, BearerTokenError

ACCESS_TOKEN = 'abcdef'


class TestExtractBearerTokenFromHttpRequest(object):
    def test_authorization_header(self):
        assert extract_bearer_token_from_http_request(authz_header='Bearer {}'.format(ACCESS_TOKEN)) == ACCESS_TOKEN

    def test_non_bearer_authorization_header(self):
        with pytest.raises(BearerTokenError):
            extract_bearer_token_from_http_request(authz_header='Basic {}'.format(ACCESS_TOKEN))

    def test_access_token_in_request(self):
        data = {
            'foo': 'bar',
            'access_token': ACCESS_TOKEN
        }
        assert extract_bearer_token_from_http_request(data) == ACCESS_TOKEN

    def test_request_without_access_token(self):
        data = {
            'foo': 'bar',
        }
        with pytest.raises(BearerTokenError):
            extract_bearer_token_from_http_request(data)
