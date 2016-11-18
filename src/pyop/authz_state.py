import logging
import time
import uuid

from oic.extension.message import TokenIntrospectionResponse
from oic.oic.message import AuthorizationRequest

from .access_token import AccessToken
from .exceptions import InvalidAccessToken
from .exceptions import InvalidAuthorizationCode
from .exceptions import InvalidRefreshToken
from .exceptions import InvalidScope
from .exceptions import InvalidSubjectIdentifier
from .util import requested_scope_is_allowed

logger = logging.getLogger(__name__)


def rand_str():
    return uuid.uuid4().hex


# TODO remove expired/invalid authorization codes/tokens from db's

class AuthorizationState(object):
    KEY_AUTHORIZATION_REQUEST = 'auth_req'

    def __init__(self, subject_identifier_factory, authorization_code_db=None, access_token_db=None,
                 refresh_token_db=None, subject_identifier_db=None, *,
                 authorization_code_lifetime=600, access_token_lifetime=3600, refresh_token_lifetime=None,
                 refresh_token_threshold=None):
        # type: (se_leg_op.token_state.SubjectIdentifierFactory, Mapping[str, Any], Mapping[str, Any],
        #        Mapping[str, Any], Mapping[str, Any], int, int, Optional[int], Optional[int]) -> None
        """
        :param subject_identifier_factory: callable to use when construction subject identifiers
        :param authorization_code_db: database for storing authorization codes, defaults to in-memory
            dict if not specified
        :param access_token_db: database for storing access tokens, defaults to in-memory
            dict if not specified
        :param refresh_token_db: database for storing refresh tokens, defaults to in-memory
            dict if not specified
        :param subject_identifier_db: database for storing subject identifiers, defaults to in-memory
            dict if not specified
        :param authorization_code_lifetime: how long before authorization codes should expire (in seconds),
            defaults to 10 minutes
        :param access_token_lifetime: how long before access tokens should expire (in seconds),
            defaults to 1 hour
        :param refresh_token_lifetime: how long before refresh tokens should expire (in seconds),
            defaults to never issuing a refresh token if not defined
        :param refresh_token_threshold: how long before refresh token expiry time a new one should be issued (in
            seconds) in a token refresh request, defaults to never issuing a new refresh token
        """

        if not subject_identifier_factory:
            raise ValueError('subject_identifier_factory can\'t be None')
        self._subject_identifier_factory = subject_identifier_factory

        self.authorization_code_lifetime = authorization_code_lifetime
        """
        Mapping of authorization codes to the subject identifier and auth request.
        """
        self.authorization_codes = authorization_code_db or {}

        self.access_token_lifetime = access_token_lifetime
        """
        Mapping of access tokens to the scope, token type, client id and subject identifier.
        """
        self.access_tokens = access_token_db or {}

        self.refresh_token_lifetime = refresh_token_lifetime
        self.refresh_token_threshold = refresh_token_threshold
        """
        Mapping of refresh tokens to access tokens.
        """
        self.refresh_tokens = refresh_token_db or {}

        """
        Mapping of user id's to subject identifiers.
        """
        self.subject_identifiers = subject_identifier_db or {}

    def create_authorization_code(self, authorization_request, subject_identifier, scope=None):
        # type: (oic.oic.message.AuthorizationRequest, str, Optional[List[str]]) -> str
        """
        Creates an authorization code bound to the authorization request and the authenticated user identified
        by the subject identifier.
        """

        if not self._is_valid_subject_identifier(subject_identifier):
            raise InvalidSubjectIdentifier('{} unknown'.format(subject_identifier))

        scope = ' '.join(scope or authorization_request['scope'])
        logger.debug('creating authz code for scope=%s', scope)

        authorization_code = rand_str()
        authz_info = {
            'used': False,
            'exp': time.time() + self.authorization_code_lifetime,
            'sub': subject_identifier,
            'granted_scope': scope,
            self.KEY_AUTHORIZATION_REQUEST: authorization_request.to_dict()
        }
        self.authorization_codes[authorization_code] = authz_info
        logger.debug('new authz_code=%s to client_id=%s for sub=%s valid_until=%s', authorization_code,
                     authorization_request['client_id'], subject_identifier, authz_info['exp'])
        return authorization_code

    def create_access_token(self, authorization_request, subject_identifier, scope=None):
        # type: (oic.oic.message.AuthorizationRequest, str, Optional[List[str]]) -> se_leg_op.access_token.AccessToken
        """
        Creates an access token bound to the authentication request and the authenticated user identified by the
        subject identifier.
        """
        if not self._is_valid_subject_identifier(subject_identifier):
            raise InvalidSubjectIdentifier('{} unknown'.format(subject_identifier))

        scope = scope or authorization_request['scope']

        return self._create_access_token(subject_identifier, authorization_request.to_dict(), ' '.join(scope))

    def _create_access_token(self, subject_identifier, auth_req, granted_scope, current_scope=None):
        # type: (str, Mapping[str, Union[str, List[str]]], str, Optional[str]) -> se_leg_op.access_token.AccessToken
        """
        Creates an access token bound to the subject identifier, client id and requested scope.
        """
        access_token = AccessToken(rand_str(), self.access_token_lifetime)

        scope = current_scope or granted_scope
        logger.debug('creating access token for scope=%s', scope)

        authz_info = {
            'iat': time.time(),
            'exp': time.time() + self.access_token_lifetime,
            'sub': subject_identifier,
            'client_id': auth_req['client_id'],
            'aud': [auth_req['client_id']],
            'scope': scope,
            'granted_scope': granted_scope,
            'token_type': access_token.BEARER_TOKEN_TYPE,
            self.KEY_AUTHORIZATION_REQUEST: auth_req
        }
        self.access_tokens[access_token.value] = authz_info

        logger.debug('new access_token=%s to client_id=%s for sub=%s valid_until=%s',
                     access_token.value, auth_req['client_id'], subject_identifier, authz_info['exp'])
        return access_token

    def exchange_code_for_token(self, authorization_code):
        # type: (str) -> se_leg_op.access_token.AccessToken
        """
        Exchanges an authorization code for an access token.
        """
        if authorization_code not in self.authorization_codes:
            raise InvalidAuthorizationCode('{} unknown'.format(authorization_code))

        authz_info = self.authorization_codes[authorization_code]
        if authz_info['used']:
            logger.debug('detected already used authz_code=%s', authorization_code)
            raise InvalidAuthorizationCode('{} has already been used'.format(authorization_code))
        elif authz_info['exp'] < time.time():
            logger.debug('detected expired authz_code=%s, now=%s > exp=%s ',
                         authorization_code, time.time(), authz_info['exp'])
            raise InvalidAuthorizationCode('{} has expired'.format(authorization_code))

        authz_info['used'] = True

        access_token = self._create_access_token(authz_info['sub'], authz_info[self.KEY_AUTHORIZATION_REQUEST],
                                                 authz_info['granted_scope'])

        logger.debug('authz_code=%s exchanged to access_token=%s', authorization_code, access_token.value)
        return access_token

    def introspect_access_token(self, access_token_value):
        # type: (str) -> Dict[str, Union[str, List[str]]]
        """
        Returns authorization data associated with the access token.
        See <a href="https://tools.ietf.org/html/rfc7662">"Token Introspection", Section 2.2</a>.
        """
        if access_token_value not in self.access_tokens:
            raise InvalidAccessToken('{} unknown'.format(access_token_value))

        authz_info = self.access_tokens[access_token_value]

        introspection = {'active': authz_info['exp'] >= time.time()}

        introspection_params = {k: v for k, v in authz_info.items() if k in TokenIntrospectionResponse.c_param}
        introspection.update(introspection_params)
        return introspection

    def create_refresh_token(self, access_token_value):
        # type: (str) -> str
        """
        Creates an refresh token bound to the specified access token.
        """
        if access_token_value not in self.access_tokens:
            raise InvalidAccessToken('{} unknown'.format(access_token_value))

        if not self.refresh_token_lifetime:
            logger.debug('no refresh token issued for for access_token=%s', access_token_value)
            return None

        refresh_token = rand_str()
        authz_info = {'access_token': access_token_value, 'exp': time.time() + self.refresh_token_lifetime}
        self.refresh_tokens[refresh_token] = authz_info

        logger.debug('issued refresh_token=%s expiring=%d for access_token=%s', refresh_token, authz_info['exp'],
                     access_token_value)
        return refresh_token

    def use_refresh_token(self, refresh_token, scope=None):
        # type (str, Optional[List[str]]) -> Tuple[se_leg_op.access_token.AccessToken, Optional[str]]
        """
        Creates a new access token, and refresh token, based on the supplied refresh token.
        :return: new access token and new refresh token if the old one had an expiration time
        """

        if refresh_token not in self.refresh_tokens:
            raise InvalidRefreshToken('{} unknown'.format(refresh_token))

        refresh_token_info = self.refresh_tokens[refresh_token]
        if 'exp' in refresh_token_info and refresh_token_info['exp'] < time.time():
            raise InvalidRefreshToken('{} has expired'.format(refresh_token))

        authz_info = self.access_tokens[refresh_token_info['access_token']]

        if scope:
            if not requested_scope_is_allowed(scope, authz_info['granted_scope']):
                logger.debug('trying to refresh token with superset scope, requested_scope=%s, granted_scope=%s',
                             scope, authz_info['granted_scope'])
                raise InvalidScope('Requested scope includes non-granted value')
            scope = ' '.join(scope)
            logger.debug('refreshing token with new scope, old_scope=%s -> new_scope=%s', authz_info['scope'], scope)
        else:
            # OAuth 2.0: scope: "[...] if omitted is treated as equal to the scope originally granted by the resource owner"
            scope = authz_info['granted_scope']

        new_access_token = self._create_access_token(authz_info['sub'], authz_info[self.KEY_AUTHORIZATION_REQUEST],
                                                     authz_info['granted_scope'], scope)

        new_refresh_token = None
        if self.refresh_token_threshold \
                and 'exp' in refresh_token_info \
                and refresh_token_info['exp'] - time.time() < self.refresh_token_threshold:
            # refresh token is close to expiry, issue a new one
            new_refresh_token = self.create_refresh_token(new_access_token.value)
        else:
            self.refresh_tokens[refresh_token]['access_token'] = new_access_token.value

        logger.debug('refreshed tokens, new_access_token=%s new_refresh_token=%s old_refresh_token=%s',
                     new_access_token, new_refresh_token, refresh_token)
        return new_access_token, new_refresh_token

    def get_subject_identifier(self, subject_type, user_id, sector_identifier=None):
        # type: (str, str, str) -> str
        """
        Returns a subject identifier for the local user identifier.
        :param subject_type: 'pairwise' or 'public', see
            <a href="http://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes">
            "OpenID Connect Core 1.0", Section 8</a>.
        :param user_id: local user identifier
        :param sector_identifier: the client's sector identifier,
            see <a href="http://openid.net/specs/openid-connect-core-1_0.html#Terminology">
            "OpenID Connect Core 1.0", Section 1.2</a>
        """

        if user_id not in self.subject_identifiers:
            self.subject_identifiers[user_id] = {}

        if subject_type == 'public':
            if 'public' not in self.subject_identifiers[user_id]:
                new_sub = self._subject_identifier_factory.create_public_identifier(user_id)
                self.subject_identifiers[user_id] = {'public': new_sub}

                logger.debug('created new public sub=% for user_id=%s',
                             self.subject_identifiers[user_id]['public'], user_id)
            sub = self.subject_identifiers[user_id]['public']
            logger.debug('returning public sub=%s', sub)
            return sub
        elif subject_type == 'pairwise':
            if not sector_identifier:
                raise ValueError('sector_identifier cannot be None or empty')

            subject_id = self._subject_identifier_factory.create_pairwise_identifier(user_id, sector_identifier)
            logger.debug('returning pairwise sub=%s for user_id=%s and sector_identifier=%s',
                         subject_id, user_id, sector_identifier)
            sub = self.subject_identifiers[user_id]
            pairwise_set = set(sub.get('pairwise', []))
            pairwise_set.add(subject_id)
            sub['pairwise'] = list(pairwise_set)
            self.subject_identifiers[user_id] = sub
            return subject_id

        raise ValueError('Unknown subject_type={}'.format(subject_type))

    def _is_valid_subject_identifier(self, sub):
        # type: (str) -> str
        """
        Determines whether the subject identifier is known.
        """

        try:
            self.get_user_id_for_subject_identifier(sub)
            return True
        except InvalidSubjectIdentifier:
            return False

    def get_user_id_for_subject_identifier(self, subject_identifier):
        for user_id, subject_identifiers in self.subject_identifiers.items():
            is_public_sub = 'public' in subject_identifiers and subject_identifier == subject_identifiers['public']
            is_pairwise_sub = 'pairwise' in subject_identifiers and subject_identifier in subject_identifiers[
                'pairwise']
            if is_public_sub or is_pairwise_sub:
                return user_id

        raise InvalidSubjectIdentifier('{} unknown'.format(subject_identifier))

    def get_authorization_request_for_code(self, authorization_code):
        # type: (str) -> oic.oic.message.AuthorizationRequest
        if authorization_code not in self.authorization_codes:
            raise InvalidAuthorizationCode('{} unknown'.format(authorization_code))

        return AuthorizationRequest().from_dict(
            self.authorization_codes[authorization_code][self.KEY_AUTHORIZATION_REQUEST])

    def get_authorization_request_for_access_token(self, access_token_value):
        # type: (str) -> oic.oic.message.AuthorizationRequest
        if access_token_value not in self.access_tokens:
            raise InvalidAccessToken('{} unknown'.format(access_token_value))

        return AuthorizationRequest().from_dict(self.access_tokens[access_token_value][self.KEY_AUTHORIZATION_REQUEST])

    def get_subject_identifier_for_code(self, authorization_code):
        # type: (str) -> oic.oic.message.AuthorizationRequest
        if authorization_code not in self.authorization_codes:
            raise InvalidAuthorizationCode('{} unknown'.format(authorization_code))

        return self.authorization_codes[authorization_code]['sub']

    def delete_state_for_subject_identifier(self, subject_identifier):
        # type (str) -> None
        if not self._is_valid_subject_identifier(subject_identifier):
            raise InvalidSubjectIdentifier('Trying to delete state for unknown subject identifier')

        for tokens in [self.authorization_codes, self.access_tokens]:
            tokens_to_remove = [k for k, v in tokens.items() if v['sub'] == subject_identifier]
            for ac in tokens_to_remove:
                tokens.pop(ac, None)
