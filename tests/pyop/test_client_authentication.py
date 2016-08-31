import base64

import pytest

from pyop.client_authentication import verify_client_authentication
from pyop.exceptions import InvalidClientAuthentication

TEST_CLIENT_ID = 'client1'
TEST_CLIENT_SECRET = 'my_secret'


class TestVerifyClientAuthentication(object):
    def create_basic_auth(self, client_id=TEST_CLIENT_ID, client_secret=TEST_CLIENT_SECRET):
        credentials = client_id + ':' + client_secret
        auth = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8')
        return 'Basic {}'.format(auth)

    @pytest.fixture(autouse=True)
    def create_request_args(self):
        self.token_request_args = {
            'grant_type': 'authorization_code',
            'code': 'code',
            'redirect_uri': 'https://client.example.com',
            'client_id': TEST_CLIENT_ID,
            'client_secret': TEST_CLIENT_SECRET
        }

        self.clients = {
            TEST_CLIENT_ID: {
                'client_secret': TEST_CLIENT_SECRET,
                'token_endpoint_auth_method': 'client_secret_post'
            }
        }

    def test_wrong_authentication_method(self):
        # do client_secret_basic, while client_secret_post is expected
        authz_header = self.create_basic_auth()
        with pytest.raises(InvalidClientAuthentication):
            verify_client_authentication(None, self.clients, authz_header)

    def test_authentication_method_defaults_to_client_secret_basic(self):
        del self.clients[TEST_CLIENT_ID]['token_endpoint_auth_method']
        authz_header = self.create_basic_auth()
        parsed_request = verify_client_authentication(self.token_request_args, self.clients, authz_header)
        assert parsed_request == self.token_request_args

    def test_client_secret_post(self):
        self.clients[TEST_CLIENT_ID]['token_endpoint_auth_method'] = 'client_secret_post'
        parsed_request = verify_client_authentication(self.token_request_args, self.clients)
        assert parsed_request == self.token_request_args

    def test_client_secret_basic(self):
        self.clients[TEST_CLIENT_ID]['token_endpoint_auth_method'] = 'client_secret_basic'
        authz_header = self.create_basic_auth()
        parsed_request = verify_client_authentication(self.token_request_args, self.clients, authz_header)
        assert parsed_request == self.token_request_args

    def test_unknown_client_id(self):
        self.token_request_args['client_id'] = 'unknown'
        with pytest.raises(InvalidClientAuthentication):
            verify_client_authentication(self.token_request_args, self.clients)

    def test_wrong_client_secret(self):
        self.token_request_args['client_secret'] = 'foobar'
        with pytest.raises(InvalidClientAuthentication):
            verify_client_authentication(self.token_request_args, self.clients)

    def test_public_client_no_auth(self):
        del self.token_request_args['client_secret']
        # public client
        self.clients[TEST_CLIENT_ID]['token_endpoint_auth_method'] = 'none'
        del self.clients[TEST_CLIENT_ID]['client_secret']

        parsed_request = verify_client_authentication(self.token_request_args, self.clients, None)
        assert parsed_request == self.token_request_args

    def test_invalid_authorization_scheme(self):
        authz_header = self.create_basic_auth()
        with pytest.raises(InvalidClientAuthentication):
            verify_client_authentication(self.token_request_args, self.clients,
                                         authz_header.replace('Basic', 'invalid'))
