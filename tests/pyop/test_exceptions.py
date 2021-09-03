from urllib.parse import urlparse, parse_qsl

from pyop.message import AuthorizationRequest
from pyop.exceptions import InvalidAuthenticationRequest


class TestInvalidAuthenticationRequest:
    def test_error_url_should_contain_state_from_authentication_request(self):
        authn_params = {'redirect_uri': 'test_redirect_uri', 'response_type': 'code', 'state': 'test_state'}
        authn_req = AuthorizationRequest().from_dict(authn_params)
        error_url = InvalidAuthenticationRequest('test', authn_req, 'invalid_request').to_error_url()

        error = dict(parse_qsl(urlparse(error_url).query))
        assert error['state'] == authn_params['state']

    def test_error_url_should_handle_unknown_response_type(self):
        authn_params = {'redirect_uri': 'test_redirect_uri', 'state': 'test_state'} # no 'response_type'
        authn_req = AuthorizationRequest().from_dict(authn_params)

        error = InvalidAuthenticationRequest('test', authn_req, 'invalid_request')
        assert error.to_error_url() is None