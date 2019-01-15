import datetime as dt
import functools
import time
from unittest.mock import patch, Mock

import pytest
from oic.oic.message import AuthorizationRequest

from pyop.authz_state import AccessToken, InvalidScope
from pyop.authz_state import AuthorizationState
from pyop.exceptions import InvalidSubjectIdentifier, InvalidAccessToken, InvalidAuthorizationCode, InvalidRefreshToken
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory

MOCK_TIME = Mock(return_value=time.mktime(dt.datetime(2016, 6, 21).timetuple()))
INVALID_INPUT = [None, '', 'noexist']


class TestAuthorizationState(object):
    TEST_TOKEN_LIFETIME = 60 * 50  # 50 minutes
    TEST_SUBJECT_IDENTIFIER = 'sub'

    def set_valid_subject_identifier(self, authorization_state):
        is_valid_sub_mock = Mock()
        is_valid_sub_mock.side_effect = lambda sub: sub == self.TEST_SUBJECT_IDENTIFIER
        authorization_state._is_valid_subject_identifier = is_valid_sub_mock

    @pytest.fixture
    def authorization_request(self):
        authn_req = AuthorizationRequest(**{'scope': 'openid', 'client_id': 'client1'})
        return authn_req

    @pytest.fixture
    def authorization_state_factory(self):
        return functools.partial(AuthorizationState, HashBasedSubjectIdentifierFactory('salt'))

    @pytest.fixture
    def authorization_state(self, authorization_state_factory):
        return authorization_state_factory(refresh_token_lifetime=3600)

    def assert_access_token(self, authorization_request, access_token, access_token_db, iat):
        assert isinstance(access_token, AccessToken)
        assert access_token.expires_in == self.TEST_TOKEN_LIFETIME
        assert access_token.value
        assert access_token.BEARER_TOKEN_TYPE == 'Bearer'

        assert access_token.value in access_token_db
        self.assert_introspected_token(authorization_request, access_token_db[access_token.value], access_token, iat)
        assert access_token_db[access_token.value]['exp'] == iat + self.TEST_TOKEN_LIFETIME

    def assert_introspected_token(self, authorization_request, token_introspection, access_token, iat):
        auth_req = authorization_request.to_dict()

        assert token_introspection['scope'] == auth_req['scope']
        assert token_introspection['client_id'] == auth_req['client_id']
        assert token_introspection['token_type'] == access_token.type
        assert token_introspection['sub'] == self.TEST_SUBJECT_IDENTIFIER
        assert token_introspection['aud'] == [auth_req['client_id']]
        assert token_introspection['iat'] == iat

    @patch('time.time', MOCK_TIME)
    def test_create_authorization_code(self, authorization_state_factory, authorization_request):
        code_lifetime = 60 * 2  # two minutes
        authorization_state = authorization_state_factory(authorization_code_lifetime=code_lifetime)
        self.set_valid_subject_identifier(authorization_state)

        authz_code = authorization_state.create_authorization_code(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        assert authz_code in authorization_state.authorization_codes
        assert authorization_state.authorization_codes[authz_code]['exp'] == int(time.time()) + code_lifetime
        assert authorization_state.authorization_codes[authz_code]['used'] is False
        assert authorization_state.authorization_codes[authz_code][AuthorizationState.KEY_AUTHORIZATION_REQUEST] == \
               authorization_request.to_dict()
        assert authorization_state.authorization_codes[authz_code]['sub'] == self.TEST_SUBJECT_IDENTIFIER

    def test_create_authorization_code_with_scope_other_than_auth_req(self, authorization_state, authorization_request):
        scope = ['openid', 'extra']
        self.set_valid_subject_identifier(authorization_state)

        authz_code = authorization_state.create_authorization_code(authorization_request,
                                                                   self.TEST_SUBJECT_IDENTIFIER, scope=scope)
        assert authorization_state.authorization_codes[authz_code]['granted_scope'] == ' '.join(scope)

    @pytest.mark.parametrize('sub', INVALID_INPUT)
    def test_create_authorization_code_with_invalid_subject_identifier(self, sub, authorization_state,
                                                                       authorization_request):
        with pytest.raises(InvalidSubjectIdentifier):
            authorization_state.create_authorization_code(authorization_request, sub)

    @patch('time.time', MOCK_TIME)
    def test_create_access_token(self, authorization_state_factory, authorization_request):
        authorization_state = authorization_state_factory(access_token_lifetime=self.TEST_TOKEN_LIFETIME)
        self.set_valid_subject_identifier(authorization_state)

        access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        self.assert_access_token(authorization_request, access_token, authorization_state.access_tokens, MOCK_TIME.return_value)

    def test_create_access_token_with_scope_other_than_auth_req(self, authorization_state, authorization_request):
        scope = ['openid', 'extra']
        self.set_valid_subject_identifier(authorization_state)

        access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER,
                                                               scope=scope)
        assert authorization_state.access_tokens[access_token.value]['scope'] == ' '.join(scope)

    @pytest.mark.parametrize('sub', INVALID_INPUT)
    def test_create_access_token_with_invalid_subject_identifier(self, sub, authorization_state, authorization_request):
        self.set_valid_subject_identifier(authorization_state)
        with pytest.raises(InvalidSubjectIdentifier):
            authorization_state.create_access_token(authorization_request, sub)

    @patch('time.time', MOCK_TIME)
    def test_introspect_access_token(self, authorization_state_factory, authorization_request):
        authorization_state = authorization_state_factory(access_token_lifetime=self.TEST_TOKEN_LIFETIME)
        self.set_valid_subject_identifier(authorization_state)

        access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        token_introspection = authorization_state.introspect_access_token(access_token.value)
        assert token_introspection['active'] is True
        self.assert_introspected_token(authorization_request, token_introspection, access_token, MOCK_TIME.return_value)

    def test_introspect_access_token_with_expired_token(self, authorization_state_factory, authorization_request):
        authorization_state = authorization_state_factory(access_token_lifetime=self.TEST_TOKEN_LIFETIME)
        self.set_valid_subject_identifier(authorization_state)

        with patch('time.time', MOCK_TIME):
            access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)

        mock_time2 = Mock()
        mock_time2.return_value = MOCK_TIME.return_value + self.TEST_TOKEN_LIFETIME + 1  # time after token expiration
        with patch('time.time', mock_time2):
            token_introspection = authorization_state.introspect_access_token(access_token.value)
        assert token_introspection['active'] is False
        self.assert_introspected_token(authorization_request, token_introspection, access_token, MOCK_TIME.return_value)

    @pytest.mark.parametrize('access_token', INVALID_INPUT)
    def test_introspect_access_token_with_invalid_access_token(self, access_token, authorization_state):
        with pytest.raises(InvalidAccessToken):
            authorization_state.introspect_access_token(access_token)

    @pytest.mark.parametrize('authz_code', INVALID_INPUT)
    def test_exchange_code_for_token_with_invalid_code(self, authz_code, authorization_state):
        with pytest.raises(InvalidAuthorizationCode):
            authorization_state.exchange_code_for_token(authz_code)

    @patch('time.time', MOCK_TIME)
    def test_exchange_code_for_token(self, authorization_state_factory, authorization_request):
        authorization_state = authorization_state_factory(access_token_lifetime=self.TEST_TOKEN_LIFETIME)
        self.set_valid_subject_identifier(authorization_state)

        authz_code = authorization_state.create_authorization_code(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        access_token = authorization_state.exchange_code_for_token(authz_code)

        self.assert_access_token(authorization_request, access_token, authorization_state.access_tokens, MOCK_TIME.return_value)
        assert authorization_state.authorization_codes[authz_code]['used'] == True

    def test_exchange_code_for_token_with_scope_other_than_auth_req(self, authorization_state,
                                                                    authorization_request):
        scope = ['openid', 'extra']
        self.set_valid_subject_identifier(authorization_state)

        authz_code = authorization_state.create_authorization_code(authorization_request, self.TEST_SUBJECT_IDENTIFIER,
                                                                   scope=scope)
        access_token = authorization_state.exchange_code_for_token(authz_code)

        assert authorization_state.access_tokens[access_token.value]['scope'] == ' '.join(scope)

    def test_exchange_code_for_token_with_expired_token(self, authorization_state_factory, authorization_request):
        code_lifetime = 2
        authorization_state = authorization_state_factory(authorization_code_lifetime=code_lifetime)
        self.set_valid_subject_identifier(authorization_state)

        with patch('time.time', MOCK_TIME):
            authz_code = authorization_state.create_authorization_code(authorization_request,
                                                                       self.TEST_SUBJECT_IDENTIFIER)

        time_mock = Mock()
        time_mock.return_value = MOCK_TIME.return_value + code_lifetime + 1  # time after code expiration
        with patch('time.time', time_mock), pytest.raises(InvalidAuthorizationCode):
            authorization_state.exchange_code_for_token(authz_code)

    def test_exchange_code_for_token_with_used_token(self, authorization_state_factory, authorization_request):
        code_lifetime = 2
        authorization_state = authorization_state_factory(authorization_code_lifetime=code_lifetime)
        self.set_valid_subject_identifier(authorization_state)

        authz_code = authorization_state.create_authorization_code(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        assert authorization_state.exchange_code_for_token(authz_code)  # successful use once
        with pytest.raises(InvalidAuthorizationCode):
            authorization_state.exchange_code_for_token(authz_code)  # fail on second use

    def test_create_refresh_token(self, authorization_state, authorization_request):
        self.set_valid_subject_identifier(authorization_state)

        access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        refresh_token = authorization_state.create_refresh_token(access_token.value)

        assert refresh_token in authorization_state.refresh_tokens
        assert authorization_state.refresh_tokens[refresh_token]['access_token'] == access_token.value
        assert 'exp' in authorization_state.refresh_tokens[refresh_token]

    def test_create_refresh_token_issues_no_refresh_token_if_no_lifetime_is_specified(self, authorization_state_factory,
                                                                                      authorization_request):
        authorization_state = authorization_state_factory(refresh_token_lifetime=None)
        self.set_valid_subject_identifier(authorization_state)

        access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        refresh_token = authorization_state.create_refresh_token(access_token.value)

        assert refresh_token is None

    @pytest.mark.parametrize('access_token', INVALID_INPUT)
    def test_create_refresh_token_with_invalid_access_token_value(self, access_token, authorization_state):
        with pytest.raises(InvalidAccessToken):
            authorization_state.create_refresh_token(access_token)

    @patch('time.time', MOCK_TIME)
    def test_create_refresh_token_with_expiration_time(self, authorization_state_factory, authorization_request):
        refresh_token_lifetime = 60 * 60 * 24  # 24 hours
        authorization_state = authorization_state_factory(refresh_token_lifetime=refresh_token_lifetime)
        self.set_valid_subject_identifier(authorization_state)

        access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        refresh_token = authorization_state.create_refresh_token(access_token.value)

        assert refresh_token in authorization_state.refresh_tokens
        assert authorization_state.refresh_tokens[refresh_token]['access_token'] == access_token.value
        assert authorization_state.refresh_tokens[refresh_token]['exp'] == int(time.time()) + refresh_token_lifetime

    def test_use_refresh_token(self, authorization_state_factory, authorization_request):
        authorization_state = authorization_state_factory(access_token_lifetime=self.TEST_TOKEN_LIFETIME,
                                                          refresh_token_lifetime=300)
        self.set_valid_subject_identifier(authorization_state)

        with patch('time.time', MOCK_TIME):
            old_access_token = authorization_state.create_access_token(authorization_request,
                                                                       self.TEST_SUBJECT_IDENTIFIER)
            refresh_token = authorization_state.create_refresh_token(old_access_token.value)

        mock_time2 = Mock()
        mock_time2.return_value = MOCK_TIME.return_value + 100
        with patch('time.time', mock_time2):
            new_access_token, new_refresh_token = authorization_state.use_refresh_token(refresh_token)

        assert new_refresh_token is None
        assert new_access_token.value != old_access_token.value
        assert new_access_token.type == old_access_token.type

        assert authorization_state.access_tokens[new_access_token.value]['exp'] > \
               authorization_state.access_tokens[old_access_token.value]['exp']
        assert authorization_state.access_tokens[new_access_token.value]['iat'] > \
               authorization_state.access_tokens[old_access_token.value]['iat']
        self.assert_access_token(authorization_request, new_access_token, authorization_state.access_tokens, mock_time2.return_value)

        assert authorization_state.refresh_tokens[refresh_token]['access_token'] == new_access_token.value

    @pytest.mark.parametrize('refresh_token', INVALID_INPUT)
    def test_use_refresh_token_with_invalid_refresh_token(self, refresh_token, authorization_state):
        with pytest.raises(InvalidRefreshToken):
            authorization_state.use_refresh_token(refresh_token)

    def test_use_refresh_token_issues_new_refresh_token_if_the_old_is_close_to_expiration(
            self, authorization_state_factory, authorization_request):
        refresh_threshold = 3600
        authorization_state = authorization_state_factory(refresh_token_lifetime=refresh_threshold * 2,
                                                          refresh_token_threshold=refresh_threshold)
        self.set_valid_subject_identifier(authorization_state)

        old_access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        refresh_token = authorization_state.create_refresh_token(old_access_token.value)

        close_to_expiration = int(time.time()) + authorization_state.refresh_token_lifetime - 50
        with patch('time.time', Mock(return_value=close_to_expiration)):
            new_access_token, new_refresh_token = authorization_state.use_refresh_token(refresh_token)

        assert new_refresh_token is not None
        assert new_refresh_token in authorization_state.refresh_tokens
        assert authorization_state.refresh_tokens[new_refresh_token]['access_token'] == new_access_token.value

    def test_use_refresh_token_doesnt_issue_new_refresh_token_if_the_old_is_far_from_expiration(
            self, authorization_state_factory, authorization_request):
        refresh_threshold = 3600
        authorization_state = authorization_state_factory(refresh_token_lifetime=refresh_threshold * 2,
                                                          refresh_token_threshold=refresh_threshold)

        self.set_valid_subject_identifier(authorization_state)

        old_access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        refresh_token = authorization_state.create_refresh_token(old_access_token.value)
        new_access_token, new_refresh_token = authorization_state.use_refresh_token(refresh_token)

        assert new_refresh_token is None

    def test_use_refresh_token_doesnt_issue_new_refresh_token_if_no_refresh_token_threshold_is_set(
            self, authorization_state_factory, authorization_request):
        authorization_state = authorization_state_factory(refresh_token_lifetime=400)

        self.set_valid_subject_identifier(authorization_state)

        old_access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        refresh_token = authorization_state.create_refresh_token(old_access_token.value)
        new_access_token, new_refresh_token = authorization_state.use_refresh_token(refresh_token)

        assert new_refresh_token is None

    def test_use_refresh_token_with_expired_refresh_token(self, authorization_state_factory, authorization_request):
        refresh_token_lifetime = 2
        authorization_state = authorization_state_factory(refresh_token_lifetime=refresh_token_lifetime)
        self.set_valid_subject_identifier(authorization_state)

        access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        with patch('time.time', MOCK_TIME):
            refresh_token = authorization_state.create_refresh_token(access_token.value)

        time_mock = Mock()
        time_mock.return_value = MOCK_TIME.return_value + refresh_token_lifetime + 1  # time after refresh_token expiration
        with patch('time.time', time_mock), pytest.raises(InvalidRefreshToken):
            authorization_state.use_refresh_token(refresh_token)

    def test_use_refresh_token_with_superset_scope(self, authorization_state, authorization_request):
        self.set_valid_subject_identifier(authorization_state)
        access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        refresh_token = authorization_state.create_refresh_token(access_token.value)
        with pytest.raises(InvalidScope):
            authorization_state.use_refresh_token(refresh_token, scope=['openid', 'extra'])

    def test_use_refresh_token_with_subset_scope(self, authorization_state, authorization_request):
        self.set_valid_subject_identifier(authorization_state)
        authorization_request['scope'] = 'openid profile'
        access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        refresh_token = authorization_state.create_refresh_token(access_token.value)
        access_token, _ = authorization_state.use_refresh_token(refresh_token, scope=['openid'])

        assert authorization_state.access_tokens[access_token.value]['scope'] == 'openid'

    def test_use_refresh_token_with_subset_scope_does_not_minimize_granted_scope(self, authorization_state,
                                                                                 authorization_request):
        scope = 'openid profile'
        self.set_valid_subject_identifier(authorization_state)
        authorization_request['scope'] = scope
        access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        refresh_token = authorization_state.create_refresh_token(access_token.value)

        # first time: issue access token with subset of granted scope
        access_token, _ = authorization_state.use_refresh_token(refresh_token, scope=['openid'])
        assert authorization_state.access_tokens[access_token.value]['scope'] == 'openid'

        # second time: issue access token with exactly granted scope
        access_token, _ = authorization_state.use_refresh_token(refresh_token)
        assert authorization_state.access_tokens[access_token.value]['scope'] == scope

    def test_use_refresh_token_without_scope(self, authorization_state, authorization_request):
        self.set_valid_subject_identifier(authorization_state)
        access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        refresh_token = authorization_state.create_refresh_token(access_token.value)
        access_token, _ = authorization_state.use_refresh_token(refresh_token)

        assert authorization_state.access_tokens[access_token.value]['scope'] == \
               ' '.join(authorization_request['scope'])

    def test_create_subject_identifier_public(self, authorization_state):
        user_id = 'test_user'
        sub1 = authorization_state.get_subject_identifier('public', user_id)
        sub2 = authorization_state.get_subject_identifier('public', user_id)
        assert sub1 == sub2
        assert authorization_state.subject_identifiers[user_id]['public'] == sub1

    def test_create_subject_identifier_pairwise_with_diffent_redirect_uris(self, authorization_state):
        user_id = 'test_user'
        sector_identifier1 = 'client1.example.com'
        sector_identifier2 = 'client2.example.com'
        sub1 = authorization_state.get_subject_identifier('pairwise', user_id, sector_identifier1)
        sub2 = authorization_state.get_subject_identifier('pairwise', user_id, sector_identifier2)
        assert sub1 != sub2
        assert all(s in authorization_state.subject_identifiers[user_id]['pairwise'] for s in [sub1, sub2])

    def test_create_subject_identifier_pairwise_with_same_hostname(self, authorization_state):
        user_id = 'test_user'
        sector_identifier = 'client.example.com'
        sub1 = authorization_state.get_subject_identifier('pairwise', user_id, sector_identifier)
        sub2 = authorization_state.get_subject_identifier('pairwise', user_id, sector_identifier)
        assert sub1 == sub2
        assert sub1 in authorization_state.subject_identifiers[user_id]['pairwise']

    def test_create_subject_identifier_pairwise_without_sector_identifier(self, authorization_state):
        with pytest.raises(ValueError):
            authorization_state.get_subject_identifier('pairwise', 'test_user', None)

    def test_create_subject_identifier_with_unknown_subject_type(self, authorization_state):
        with pytest.raises(ValueError):
            authorization_state.get_subject_identifier('unknown', 'test_user', None)

    @pytest.mark.parametrize('subject_type', [
        'public',
        'pairwise'
    ])
    def test_is_valid_subject_identifier(self, subject_type, authorization_state):
        sub = authorization_state.get_subject_identifier(subject_type, 'test_user', 'client.example.com')
        assert authorization_state._is_valid_subject_identifier(sub) is True

    def test_get_authentication_request_for_code(self, authorization_state, authorization_request):
        self.set_valid_subject_identifier(authorization_state)
        authz_code = authorization_state.create_authorization_code(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        request = authorization_state.get_authorization_request_for_code(authz_code)
        assert request.to_dict() == authorization_request.to_dict()

    def test_get_authentication_request_for_access_token(self, authorization_state, authorization_request):
        self.set_valid_subject_identifier(authorization_state)
        access_token = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        request = authorization_state.get_authorization_request_for_access_token(access_token.value)
        assert request.to_dict() == authorization_request.to_dict()

    def test_get_subject_identifier_for_code(self, authorization_state, authorization_request):
        self.set_valid_subject_identifier(authorization_state)
        authz_code = authorization_state.create_authorization_code(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        sub = authorization_state.get_subject_identifier_for_code(authz_code)
        assert sub == self.TEST_SUBJECT_IDENTIFIER

    def test_remove_state_for_subject_identifier(self, authorization_state, authorization_request):
        self.set_valid_subject_identifier(authorization_state)
        authz_code1 = authorization_state.create_authorization_code(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        authz_code2 = authorization_state.create_authorization_code(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        access_token1 = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)
        access_token2 = authorization_state.create_access_token(authorization_request, self.TEST_SUBJECT_IDENTIFIER)

        authorization_state.delete_state_for_subject_identifier(self.TEST_SUBJECT_IDENTIFIER)

        for ac in [authz_code1, authz_code2]:
            assert ac not in authorization_state.authorization_codes
        for at in [access_token1, access_token2]:
            assert at.value not in authorization_state.access_tokens

    def test_remove_state_for_unknown_subject_identifier(self, authorization_state):
        with pytest.raises(InvalidSubjectIdentifier):
            authorization_state.delete_state_for_subject_identifier('unknown')
