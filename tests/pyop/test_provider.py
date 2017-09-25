import datetime as dt
import json
import time
from collections import Counter
from unittest.mock import Mock, patch
from urllib.parse import urlencode

import pytest
from Cryptodome.PublicKey import RSA
from jwkest import jws
from jwkest.jwk import RSAKey
from oic import rndstr
from oic.oauth2.message import MissingRequiredValue, MissingRequiredAttribute
from oic.oic import PREFERENCE2PROVIDER
from oic.oic.message import IdToken, AuthorizationRequest, ClaimsRequest, Claims, EndSessionRequest, EndSessionResponse

from pyop.access_token import BearerTokenError
from pyop.authz_state import AuthorizationState
from pyop.client_authentication import InvalidClientAuthentication
from pyop.exceptions import InvalidAuthenticationRequest, AuthorizationError, InvalidTokenRequest, \
    InvalidClientRegistrationRequest, InvalidAccessToken, InvalidAuthorizationCode, InvalidSubjectIdentifier
from pyop.provider import Provider, redirect_uri_is_in_registered_redirect_uris, \
    response_type_is_in_registered_response_types
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo

TEST_CLIENT_ID = 'client1'
TEST_CLIENT_SECRET = 'secret'
INVALID_TEST_CLIENT_ID = 'invalid_client'
INVALID_TEST_CLIENT_SECRET = 'invalid_secret'
TEST_REDIRECT_URI = 'https://client.example.com'
ISSUER = 'https://provider.example.com'
TEST_USER_ID = 'user1'

MOCK_TIME = Mock(return_value=time.mktime(dt.datetime(2016, 6, 21).timetuple()))


def rsa_key():
    return RSAKey(key=RSA.generate(1024), use="sig", alg="RS256", kid=rndstr(4))


def provide_configuration():
    conf = {
        'issuer': ISSUER,
        'jwks_uri': '/jwks',
        'authorization_endpoint': '/authorization',
        'token_endpoint': '/token'
    }
    return conf


def assert_id_token_base_claims(jws, verification_key, provider, auth_req):
    id_token = IdToken().from_jwt(jws, key=[verification_key])
    assert id_token['nonce'] == auth_req['nonce']
    assert id_token['iss'] == ISSUER
    assert provider.authz_state.get_user_id_for_subject_identifier(id_token['sub']) == TEST_USER_ID
    assert id_token['iat'] == MOCK_TIME.return_value
    assert id_token['exp'] == id_token['iat'] + provider.id_token_lifetime
    assert TEST_CLIENT_ID in id_token['aud']

    return id_token


@pytest.fixture
def auth_req_args(request):
    request.instance.authn_request_args = {
        'scope': 'openid',
        'response_type': 'code',
        'client_id': TEST_CLIENT_ID,
        'redirect_uri': TEST_REDIRECT_URI,
        'state': 'state',
        'nonce': 'nonce'
    }


@pytest.fixture
def inject_provider(request):
    clients = {
        TEST_CLIENT_ID: {
            'subject_type': 'pairwise',
            'redirect_uris': [TEST_REDIRECT_URI],
            'response_types': ['code'],
            'client_secret': TEST_CLIENT_SECRET,
            'token_endpoint_auth_method': 'client_secret_post',
            'post_logout_redirect_uris': ['https://client.example.com/post_logout']
        },
        INVALID_TEST_CLIENT_ID: {
            'subject_type': 'pairwise',
            'redirect_uris': 'http://invalid.redirect.loc',
            'response_types': ['code'],
            'client_secret': INVALID_TEST_CLIENT_SECRET,
            'token_endpoint_auth_method': 'client_secret_post',
            'post_logout_redirect_uris': ['https://client.example.com/post_logout']
        }
    }

    userinfo = Userinfo({
        TEST_USER_ID: {
            'name': 'The T. Tester',
            'family_name': 'Tester',
            'given_name': 'The',
            'middle_name': 'Theodore',
            'nickname': 'testster',
            'email': 'testster@example.com',
        }
    })
    request.instance.provider = Provider(rsa_key(), provide_configuration(),
                                         AuthorizationState(HashBasedSubjectIdentifierFactory('salt')),
                                         clients, userinfo)


@pytest.mark.usefixtures('inject_provider', 'auth_req_args')
class TestProviderParseAuthenticationRequest(object):
    def test_parse_authentication_request(self):
        nonce = 'nonce'
        self.authn_request_args['nonce'] = nonce

        received_request = self.provider.parse_authentication_request(urlencode(self.authn_request_args))
        assert received_request.to_dict() == self.authn_request_args

    def test_reject_request_with_missing_required_parameter(self):
        del self.authn_request_args['redirect_uri']

        with pytest.raises(InvalidAuthenticationRequest) as exc:
            self.provider.parse_authentication_request(urlencode(self.authn_request_args))
        assert isinstance(exc.value.__cause__, MissingRequiredAttribute)

    def test_reject_request_with_scope_without_openid(self):
        self.authn_request_args['scope'] = 'foobar'  # does not contain 'openid'

        with pytest.raises(InvalidAuthenticationRequest) as exc:
            self.provider.parse_authentication_request(urlencode(self.authn_request_args))
        assert isinstance(exc.value.__cause__, MissingRequiredValue)

    def test_custom_validation_hook_reject(self):
        class TestException(Exception):
            pass

        def fail_all_requests(auth_req):
            raise InvalidAuthenticationRequest("Test exception", auth_req) from TestException()

        self.provider.authentication_request_validators.append(fail_all_requests)
        with pytest.raises(InvalidAuthenticationRequest) as exc:
            self.provider.parse_authentication_request(urlencode(self.authn_request_args))

        assert isinstance(exc.value.__cause__, TestException)

    def test_redirect_uri_not_matching_registered_redirect_uris(self):
        self.authn_request_args['redirect_uri'] = 'https://something.example.com'
        with pytest.raises(InvalidAuthenticationRequest):
            self.provider.parse_authentication_request(urlencode(self.authn_request_args))

    def test_response_type_not_matching_registered_response_types(self):
        self.authn_request_args['response_type'] = 'id_token'
        with pytest.raises(InvalidAuthenticationRequest):
            self.provider.parse_authentication_request(urlencode(self.authn_request_args))

    def test_unknown_client_id(self):
        self.authn_request_args['client_id'] = 'unknown'
        with pytest.raises(InvalidAuthenticationRequest):
            self.provider.parse_authentication_request(urlencode(self.authn_request_args))

    def test_include_userinfo_claims_request_with_response_type_id_token(self):
        self.authn_request_args['claims'] = ClaimsRequest(userinfo=Claims(nickname=None)).to_json()
        self.provider.clients[TEST_CLIENT_ID]['response_types'] = ['id_token']
        self.authn_request_args['response_type'] = 'id_token'
        with pytest.raises(InvalidAuthenticationRequest):
            self.provider.parse_authentication_request(urlencode(self.authn_request_args))


@pytest.mark.usefixtures('auth_req_args')
class TestAuthenticationRequestValidators(object):
    @pytest.fixture
    def provider_mock(self):
        provider = Mock()
        provider.clients = Mock()
        provider.clients.__getitem__ = Mock(return_value={})
        return provider

    def test_redirect_uri_is_in_registered_redirect_uris_with_no_redirect_uris(self, provider_mock):
        auth_req = AuthorizationRequest().from_dict(self.authn_request_args)
        with pytest.raises(InvalidAuthenticationRequest):
            redirect_uri_is_in_registered_redirect_uris(provider_mock, auth_req)

    def test_response_type_is_in_registered_response_types_with_no_response_types(self, provider_mock):
        auth_req = AuthorizationRequest().from_dict(self.authn_request_args)
        with pytest.raises(InvalidAuthenticationRequest):
            response_type_is_in_registered_response_types(provider_mock, auth_req)


@pytest.mark.usefixtures('inject_provider', 'auth_req_args')
class TestProviderAuthorize(object):
    def test_authorize(self):
        auth_req = AuthorizationRequest().from_dict(self.authn_request_args)
        resp = self.provider.authorize(auth_req, TEST_USER_ID)
        assert resp['code'] in self.provider.authz_state.authorization_codes
        assert resp['state'] == self.authn_request_args['state']

    def test_authorize_with_custom_sub(self, monkeypatch):
        sub = 'test_sub1'
        monkeypatch.setitem(self.provider.userinfo._db[TEST_USER_ID], 'sub', sub)
        auth_req = AuthorizationRequest().from_dict(self.authn_request_args)
        resp = self.provider.authorize(auth_req, TEST_USER_ID)
        assert resp['code'] in self.provider.authz_state.authorization_codes
        assert resp['state'] == self.authn_request_args['state']
        assert self.provider.authz_state.authorization_codes[resp['code']]['sub'] == sub

    @patch('time.time', MOCK_TIME)
    @pytest.mark.parametrize('extra_claims', [
        {'foo': 'bar'},
        lambda user_id, client_id: {'foo': 'bar'}
    ])
    def test_authorize_with_extra_id_token_claims(self, extra_claims):
        self.authn_request_args['response_type'] = ['id_token']  # make sure ID Token is produced
        auth_req = AuthorizationRequest().from_dict(self.authn_request_args)
        resp = self.provider.authorize(auth_req, TEST_USER_ID, extra_claims)
        id_token = assert_id_token_base_claims(resp['id_token'], self.provider.signing_key, self.provider, auth_req)
        assert id_token['foo'] == 'bar'

    def test_authorize_include_user_claims_from_scope_in_id_token_if_no_userinfo_req_can_be_made(self):
        self.authn_request_args['response_type'] = 'id_token'
        self.authn_request_args['scope'] = 'openid profile'
        self.authn_request_args['claims'] = ClaimsRequest(id_token=Claims(email={'essential': True}))
        auth_req = AuthorizationRequest().from_dict(self.authn_request_args)
        resp = self.provider.authorize(auth_req, TEST_USER_ID)

        id_token = IdToken().from_jwt(resp['id_token'], key=[self.provider.signing_key])
        # verify all claims are part of the ID Token
        assert all(id_token[claim] == value for claim, value in self.provider.userinfo[TEST_USER_ID].items())

    @patch('time.time', MOCK_TIME)
    def test_authorize_includes_requested_id_token_claims_even_if_token_request_can_be_made(self):
        self.authn_request_args['response_type'] = ['id_token', 'token']
        self.authn_request_args['claims'] = ClaimsRequest(id_token=Claims(email=None))
        auth_req = AuthorizationRequest().from_dict(self.authn_request_args)
        resp = self.provider.authorize(auth_req, TEST_USER_ID)
        id_token = assert_id_token_base_claims(resp['id_token'], self.provider.signing_key, self.provider, auth_req)
        assert id_token['email'] == self.provider.userinfo[TEST_USER_ID]['email']

    @patch('time.time', MOCK_TIME)
    def test_hybrid_flow(self):
        self.authn_request_args['response_type'] = 'code id_token token'
        auth_req = AuthorizationRequest().from_dict(self.authn_request_args)
        resp = self.provider.authorize(auth_req, TEST_USER_ID, extra_id_token_claims={'foo': 'bar'})

        assert resp['state'] == self.authn_request_args['state']
        assert resp['code'] in self.provider.authz_state.authorization_codes

        assert resp['access_token'] in self.provider.authz_state.access_tokens
        assert resp['expires_in'] == self.provider.authz_state.access_token_lifetime
        assert resp['token_type'] == 'Bearer'

        id_token = IdToken().from_jwt(resp['id_token'], key=[self.provider.signing_key])
        assert_id_token_base_claims(resp['id_token'], self.provider.signing_key, self.provider, self.authn_request_args)
        assert id_token["c_hash"] == jws.left_hash(resp['code'].encode('utf-8'), 'HS256')
        assert id_token["at_hash"] == jws.left_hash(resp['access_token'].encode('utf-8'), 'HS256')
        assert id_token['foo'] == 'bar'

    @pytest.mark.parametrize('claims_location', [
        'id_token',
        'userinfo'
    ])
    def test_with_requested_sub_not_matching(self, claims_location):
        self.authn_request_args['claims'] = ClaimsRequest(**{claims_location: Claims(sub={'value': 'nomatch'})})
        auth_req = AuthorizationRequest().from_dict(self.authn_request_args)
        with pytest.raises(AuthorizationError):
            self.provider.authorize(auth_req, TEST_USER_ID)

    def test_with_multiple_requested_sub(self):
        self.authn_request_args['claims'] = ClaimsRequest(userinfo=Claims(sub={'value': 'nomatch1'}),
                                                          id_token=Claims(sub={'value': 'nomatch2'}))
        auth_req = AuthorizationRequest().from_dict(self.authn_request_args)
        with pytest.raises(AuthorizationError) as exc:
            self.provider.authorize(auth_req, TEST_USER_ID)

        assert 'different' in str(exc.value)


@pytest.mark.usefixtures('inject_provider', 'auth_req_args')
class TestProviderHandleTokenRequest(object):
    def create_authz_code(self, extra_auth_req_params=None):
        sub = self.provider.authz_state.get_subject_identifier('pairwise', TEST_USER_ID, 'client1.example.com')

        if extra_auth_req_params:
            self.authn_request_args.update(extra_auth_req_params)
        auth_req = AuthorizationRequest().from_dict(self.authn_request_args)
        return self.provider.authz_state.create_authorization_code(auth_req, sub)

    def create_refresh_token(self):
        sub = self.provider.authz_state.get_subject_identifier('pairwise', TEST_USER_ID, 'client1.example.com')
        auth_req = AuthorizationRequest().from_dict(self.authn_request_args)
        access_token = self.provider.authz_state.create_access_token(auth_req, sub)
        return self.provider.authz_state.create_refresh_token(access_token.value)

    @pytest.fixture(autouse=True)
    def create_token_request_args(self):
        self.authorization_code_exchange_request_args = {
            'grant_type': 'authorization_code',
            'code': None,
            'redirect_uri': 'https://client.example.com',
            'client_id': TEST_CLIENT_ID,
            'client_secret': TEST_CLIENT_SECRET
        }

        self.refresh_token_request_args = {
            'grant_type': 'refresh_token',
            'refresh_token': None,
            'scope': 'openid',
            'client_id': TEST_CLIENT_ID,
            'client_secret': TEST_CLIENT_SECRET
        }

    @patch('time.time', MOCK_TIME)
    def test_code_exchange_request(self):
        self.authorization_code_exchange_request_args['code'] = self.create_authz_code()
        response = self.provider._do_code_exchange(self.authorization_code_exchange_request_args, None)
        assert response['access_token'] in self.provider.authz_state.access_tokens
        assert_id_token_base_claims(response['id_token'], self.provider.signing_key, self.provider,
                                    self.authn_request_args)

    @patch('time.time', MOCK_TIME)
    def test_code_exchange_request_with_claims_requested_in_id_token(self):
        claims_req = {'claims': ClaimsRequest(id_token=Claims(email=None))}
        self.authorization_code_exchange_request_args['code'] = self.create_authz_code(extra_auth_req_params=claims_req)
        response = self.provider._do_code_exchange(self.authorization_code_exchange_request_args, None)
        assert response['access_token'] in self.provider.authz_state.access_tokens
        id_token = assert_id_token_base_claims(response['id_token'], self.provider.signing_key, self.provider,
                                               self.authn_request_args)
        assert id_token['email'] == self.provider.userinfo[TEST_USER_ID]['email']

    @patch('time.time', MOCK_TIME)
    @pytest.mark.parametrize('extra_claims', [
        {'foo': 'bar'},
        lambda user_id, client_id: {'foo': 'bar'}
    ])
    def test_handle_token_request_with_extra_id_token_claims(self, extra_claims):
        self.authorization_code_exchange_request_args['code'] = self.create_authz_code()
        response = self.provider.handle_token_request(urlencode(self.authorization_code_exchange_request_args),
                                                      extra_id_token_claims=extra_claims)
        assert response['access_token'] in self.provider.authz_state.access_tokens
        id_token = assert_id_token_base_claims(response['id_token'], self.provider.signing_key, self.provider,
                                               self.authn_request_args)
        assert id_token['foo'] == 'bar'

    def test_handle_token_request_reject_invalid_client_authentication(self):
        self.authorization_code_exchange_request_args['code'] = self.create_authz_code()
        self.authorization_code_exchange_request_args['client_secret'] = 'invalid'
        with pytest.raises(InvalidClientAuthentication):
            self.provider.handle_token_request(urlencode(self.authorization_code_exchange_request_args),
                                               extra_id_token_claims={'foo': 'bar'})

    def test_handle_token_request_reject_code_not_issued_to_client(self):
        self.authorization_code_exchange_request_args['client_id'] = INVALID_TEST_CLIENT_ID
        self.authorization_code_exchange_request_args['client_secret'] = INVALID_TEST_CLIENT_SECRET
        self.authorization_code_exchange_request_args['code'] = self.create_authz_code()
        with pytest.raises(InvalidAuthorizationCode):
            self.provider.handle_token_request(urlencode(self.authorization_code_exchange_request_args))

    def test_handle_token_request_reject_invalid_redirect_uri_in_exchange_request(self):
        self.authorization_code_exchange_request_args['redirect_uri'] = 'https://invalid.com'
        self.authorization_code_exchange_request_args['code'] = self.create_authz_code()
        with pytest.raises(InvalidTokenRequest):
            self.provider.handle_token_request(urlencode(self.authorization_code_exchange_request_args))

    def test_handle_token_request_reject_invalid_grant_type(self):
        self.authorization_code_exchange_request_args['grant_type'] = 'invalid'
        self.authorization_code_exchange_request_args['code'] = self.create_authz_code()
        with pytest.raises(InvalidTokenRequest):
            self.provider.handle_token_request(urlencode(self.authorization_code_exchange_request_args))

    def test_handle_token_request_reject_missing_grant_type(self):
        del self.authorization_code_exchange_request_args['grant_type']
        self.authorization_code_exchange_request_args['code'] = self.create_authz_code()
        with pytest.raises(InvalidTokenRequest):
            self.provider.handle_token_request(urlencode(self.authorization_code_exchange_request_args))

    def test_refresh_request(self):
        self.provider.authz_state = AuthorizationState(HashBasedSubjectIdentifierFactory('salt'),
                                                       refresh_token_lifetime=600)
        self.refresh_token_request_args['refresh_token'] = self.create_refresh_token()
        response = self.provider.handle_token_request(urlencode(self.refresh_token_request_args))
        assert response['access_token'] in self.provider.authz_state.access_tokens
        assert 'refresh_token' not in response

    def test_refresh_request_with_refresh_token_close_to_expiry_issues_new_refresh_token(self):
        self.provider.authz_state = AuthorizationState(HashBasedSubjectIdentifierFactory('salt'),
                                                       refresh_token_lifetime=10,
                                                       refresh_token_threshold=2)
        self.refresh_token_request_args['refresh_token'] = self.create_refresh_token()

        close_to_expiration = int(time.time()) + self.provider.authz_state.refresh_token_lifetime - 1
        with patch('time.time', Mock(return_value=close_to_expiration)):
            response = self.provider.handle_token_request(urlencode(self.refresh_token_request_args))
        assert response['access_token'] in self.provider.authz_state.access_tokens
        assert response['refresh_token'] in self.provider.authz_state.refresh_tokens

    def test_refresh_request_without_scope_parameter_defaults_to_scope_from_authentication_request(self):
        self.provider.authz_state = AuthorizationState(HashBasedSubjectIdentifierFactory('salt'),
                                                       refresh_token_lifetime=600)
        self.refresh_token_request_args['refresh_token'] = self.create_refresh_token()
        del self.refresh_token_request_args['scope']
        response = self.provider.handle_token_request(urlencode(self.refresh_token_request_args))
        assert response['access_token'] in self.provider.authz_state.access_tokens
        assert self.provider.authz_state.access_tokens[response['access_token']]['scope'] == self.authn_request_args[
            'scope']

    @pytest.mark.parametrize('missing_parameter', [
        'grant_type',
        'code',
        'redirect_uri'
    ])
    def test_code_exchange_request_with_missing_parameter(self, missing_parameter):
        request_args = {
            'grant_type': 'authorization_code',
            'code': None,
            'redirect_uri': TEST_REDIRECT_URI,
        }
        del request_args[missing_parameter]
        with pytest.raises(InvalidTokenRequest):
            self.provider._do_code_exchange(request_args)

    @pytest.mark.parametrize('missing_parameter', [
        'grant_type',
        'refresh_token',
    ])
    def test_refresh_token_request_with_missing_parameter(self, missing_parameter):
        request_args = {
            'grant_type': 'refresh_token',
            'refresh_token': None,
        }
        del request_args[missing_parameter]
        with pytest.raises(InvalidTokenRequest):
            self.provider._do_token_refresh(request_args)


@pytest.mark.usefixtures('inject_provider', 'auth_req_args')
class TestProviderHandleUserinfoRequest(object):
    def create_access_token(self, extra_auth_req_params=None):
        sub = self.provider.authz_state.get_subject_identifier('pairwise', TEST_USER_ID, 'client1.example.com')

        if extra_auth_req_params:
            self.authn_request_args.update(extra_auth_req_params)

        auth_req = AuthorizationRequest().from_dict(self.authn_request_args)
        access_token = self.provider.authz_state.create_access_token(auth_req, sub)
        return access_token.value

    def test_handle_userinfo(self):
        claims_request = ClaimsRequest(userinfo=Claims(email=None))
        access_token = self.create_access_token({'scope': 'openid profile', 'claims': claims_request})
        response = self.provider.handle_userinfo_request(urlencode({'access_token': access_token}))

        response_sub = response['sub']
        del response['sub']
        assert response.to_dict() == self.provider.userinfo[TEST_USER_ID]
        assert self.provider.authz_state.get_user_id_for_subject_identifier(response_sub) == TEST_USER_ID

    def test_handle_userinfo_with_custom_sub(self, monkeypatch):
        sub = 'test_sub1'
        monkeypatch.setitem(self.provider.userinfo._db[TEST_USER_ID], 'sub', sub)
        claims_request = ClaimsRequest(userinfo=Claims(email=None))
        access_token = self.create_access_token({'scope': 'openid profile', 'claims': claims_request})
        response = self.provider.handle_userinfo_request(urlencode({'access_token': access_token}))

        assert response['sub'] == sub

    def test_handle_userinfo_rejects_request_missing_access_token(self):
        with pytest.raises(BearerTokenError) as exc:
            self.provider.handle_userinfo_request()

    def test_handle_userinfo_rejects_invalid_access_token(self):
        access_token = self.create_access_token()
        self.provider.authz_state.access_tokens[access_token]['exp'] = 0
        with pytest.raises(InvalidAccessToken):
            self.provider.handle_userinfo_request(urlencode({'access_token': access_token}))


@pytest.mark.usefixtures('inject_provider')
class TestProviderHandleRegistrationRequest(object):
    def test_handle_registration_request(self):
        request = {'redirect_uris': ['https://client.example.com/redirect']}
        response = self.provider.handle_client_registration_request(json.dumps(request))
        assert 'client_id' in response
        assert 'client_id_issued_at' in response
        assert 'client_secret' in response
        assert response['client_secret_expires_at'] == 0
        assert all(k in response.items() for k in request.items())

        assert response['client_id'] in self.provider.clients

    def test_rejects_invalid_request(self):
        request = {'application_type': 'web', 'client_name': 'test client'}  # missing 'redirect_uris'
        with pytest.raises(InvalidClientRegistrationRequest):
            self.provider.handle_client_registration_request(json.dumps(request))

    @pytest.mark.parametrize('client_preference, provider_capability, client_value, provider_value', [
        ('request_object_signing_alg', 'request_object_signing_alg_values_supported',
         'HS256', ['none', 'RS256']),
        ('request_object_encryption_alg', 'request_object_encryption_alg_values_supported',
         'RSA-OAEP-256', ['RSA-OAEP', 'ECDH-ES']),
        ('request_object_encryption_enc', 'request_object_encryption_enc_values_supported',
         'A192CBC-HS384', ['A128CBC-HS256', 'A256CBC-HS512 ']),
        ('userinfo_signed_response_alg', 'userinfo_signing_alg_values_supported',
         'HS256', ['none', 'RS256']),
        ('userinfo_encrypted_response_alg', 'userinfo_encryption_alg_values_supported',
         'RSA-OAEP-256', ['RSA-OAEP', 'ECDH-ES']),
        ('userinfo_encrypted_response_enc', 'userinfo_encryption_enc_values_supported',
         'A192CBC-HS384', ['A128CBC-HS256', 'A256CBC-HS512 ']),
        ('id_token_signed_response_alg', 'id_token_signing_alg_values_supported',
         'HS256', ['none', 'RS256']),
        ('id_token_encrypted_response_alg', 'id_token_encryption_alg_values_supported',
         'RSA-OAEP-256', ['RSA-OAEP', 'ECDH-ES']),
        ('id_token_encrypted_response_enc', 'id_token_encryption_enc_values_supported',
         'A192CBC-HS384', ['A128CBC-HS256', 'A256CBC-HS512 ']),
        ('default_acr_values', 'acr_values_supported',
         ['1', '2'], ['3', '4']),
        ('subject_type', 'subject_types_supported',
         'public', ['pairwise']),
        ('token_endpoint_auth_method', 'token_endpoint_auth_methods_supported',
         'private_key_jwt', ['client_secret_post', 'client_secret_basic']),
        ('token_endpoint_auth_signing_alg', 'token_endpoint_auth_signing_alg_values_supported',
         'HS256', ['none', 'RS256']),
        ('response_types', 'response_types_supported',
         ['id_token token'], ['code', 'code token']),
        ('grant_types', 'grant_types_supported',
         'implicit', ['authorization_code'])
    ])
    def test_rejects_mismatching_request(self, client_preference, provider_capability, client_value, provider_value):
        request = {'redirect_uris': ['https://client.example.com/redirect']}
        provider_capabilities = provide_configuration()

        if client_preference.startswith(('request_object_encryption', 'id_token_encrypted', 'userinfo_encrypted')):
            # provide default value for the metadata params that come in pairs
            param = client_preference[:-4]
            alg_param = param + '_alg'
            request[alg_param] = 'RSA-OAEP'
            provider_capabilities[PREFERENCE2PROVIDER[alg_param]] = ['RSA-OAEP']
            enc_param = param + '_enc'
            request[enc_param] = 'A192CBC-HS256'
            provider_capabilities[PREFERENCE2PROVIDER[enc_param]] = ['A192CBC-HS256']

        request[client_preference] = client_value
        provider_capabilities[provider_capability] = provider_value
        provider = Provider(rsa_key(), provider_capabilities,
                            AuthorizationState(HashBasedSubjectIdentifierFactory('salt')), {}, None)
        with pytest.raises(InvalidClientRegistrationRequest):
            provider.handle_client_registration_request(json.dumps(request))

    @pytest.mark.parametrize('client_preference, provider_capability, client_value, provider_value', [
        ('response_types', 'response_types_supported',
         ['code id_token token', 'code', 'id_token', 'id_token token'],
         ['code id_token token', 'id_token token']),
        ('default_acr_values', 'acr_values_supported',
         ['1', '2', '3'], ['2', '3', '4']),
    ])
    def test_matches_common_set_of_metadata_values(self, client_preference, provider_capability,
                                                   client_value, provider_value):
        provider_capabilities = provide_configuration()
        provider_capabilities.update({provider_capability: provider_value})
        provider = Provider(rsa_key(), provider_capabilities,
                            AuthorizationState(HashBasedSubjectIdentifierFactory('salt')), {}, None)
        request = {'redirect_uris': ['https://client.example.com/redirect'], client_preference: client_value}
        response = provider.handle_client_registration_request(json.dumps(request))
        expected_values = set(client_value).intersection(provider_value)
        assert Counter(frozenset(v.split()) for v in response[client_preference]) == \
               Counter(frozenset(v.split()) for v in expected_values)

    def test_match_space_separated_response_type_without_order(self):
        registration_request = {'redirect_uris': ['https://client.example.com/redirect'],
                                'response_types': ['id_token token']}
        # should not raise an exception
        assert self.provider.handle_client_registration_request(json.dumps(registration_request))

    def test_client_can_use_registered_space_separated_response_type_in_authentication_request(self):
        response_type = 'id_token token'
        registration_request = {'redirect_uris': ['https://client.example.com/redirect'],
                                'response_types': [response_type]}
        registration_response = self.provider.handle_client_registration_request(json.dumps(registration_request))

        authentication_request = {'client_id': registration_response['client_id'],
                                  'redirect_uri': 'https://client.example.com/redirect',
                                  'scope': 'openid',
                                  'nonce': 'nonce',
                                  'response_type': response_type}
        # should not raise an exception
        assert self.provider.parse_authentication_request(urlencode(authentication_request))


class TestProviderProviderConfiguration(object):
    def test_provider_configuration(self):
        config = provide_configuration()
        config.update({'foo': 'bar', 'abc': 'xyz'})
        provider = Provider(None, config, None, None, None)
        provider_config = provider.provider_configuration
        assert all(k in provider_config for k in config)


class TestProviderJWKS(object):
    def test_jwks(self):
        provider = Provider(rsa_key(), provide_configuration(), None, None, None)
        assert provider.jwks == {'keys': [provider.signing_key.serialize()]}


@pytest.mark.usefixtures('inject_provider')
class TestRPInitiatedLogout(object):
    def test_logout_user_with_subject_identifier(self):
        auth_req = AuthorizationRequest(response_type='code id_token token', scope='openid', client_id='client1',
                                        redirect_uri='https://client.example.com/redirect')
        auth_resp = self.provider.authorize(auth_req, 'user1')

        id_token = IdToken().from_jwt(auth_resp['id_token'], key=[self.provider.signing_key])
        self.provider.logout_user(subject_identifier=id_token['sub'])
        with pytest.raises(InvalidAccessToken):
            self.provider.authz_state.introspect_access_token(auth_resp['access_token'])
        with pytest.raises(InvalidAuthorizationCode):
            self.provider.authz_state.exchange_code_for_token(auth_resp['code'])

    def test_logout_user_with_id_token_hint(self):
        auth_req = AuthorizationRequest(response_type='code id_token token', scope='openid', client_id='client1',
                                        redirect_uri='https://client.example.com/redirect')
        auth_resp = self.provider.authorize(auth_req, 'user1')

        self.provider.logout_user(end_session_request=EndSessionRequest(id_token_hint=auth_resp['id_token']))
        with pytest.raises(InvalidAccessToken):
            self.provider.authz_state.introspect_access_token(auth_resp['access_token'])
        with pytest.raises(InvalidAuthorizationCode):
            self.provider.authz_state.exchange_code_for_token(auth_resp['code'])

    def test_logout_user_with_unknown_subject_identifier(self):
        with pytest.raises(InvalidSubjectIdentifier):
            self.provider.logout_user(subject_identifier='unknown')

    def test_post_logout_redirect(self):
        auth_req = AuthorizationRequest(response_type='code id_token token', scope='openid', client_id='client1',
                                        redirect_uri='https://client.example.com/redirect')
        auth_resp = self.provider.authorize(auth_req, 'user1')
        end_session_request = EndSessionRequest(id_token_hint=auth_resp['id_token'],
                                                post_logout_redirect_uri='https://client.example.com/post_logout',
                                                state='state')
        redirect_url = self.provider.do_post_logout_redirect(end_session_request)
        assert redirect_url == EndSessionResponse(state='state').request('https://client.example.com/post_logout')

    def test_post_logout_redirect_without_post_logout_redirect_uri(self):
        assert self.provider.do_post_logout_redirect(EndSessionRequest()) is None

    def test_post_logout_redirect_with_unknown_client_for_post_logout_redirect_uri(self):
        end_session_request = EndSessionRequest(post_logout_redirect_uri='https://client.example.com/post_logout')
        assert self.provider.do_post_logout_redirect(end_session_request) is None

    def test_post_logout_redirect_with_unknown_post_logout_redirect_uri(self):
        auth_req = AuthorizationRequest(response_type='code id_token token', scope='openid', client_id='client1',
                                        redirect_uri='https://client.example.com/redirect')
        auth_resp = self.provider.authorize(auth_req, 'user1')
        end_session_request = EndSessionRequest(id_token_hint=auth_resp['id_token'],
                                                post_logout_redirect_uri='https://client.example.com/unknown')
        assert self.provider.do_post_logout_redirect(end_session_request) is None
