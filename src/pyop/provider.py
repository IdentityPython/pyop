import copy
import functools
import logging
import time
import uuid
from urllib.parse import parse_qsl
from urllib.parse import urlparse

from jwkest import jws
from oic import rndstr
from oic.exception import MessageException
from oic.oic import PREFERENCE2PROVIDER
from oic.oic import scope2claims
from oic.oic.message import AccessTokenRequest
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AuthorizationResponse
from oic.oic.message import EndSessionRequest
from oic.oic.message import EndSessionResponse
from oic.oic.message import IdToken
from oic.oic.message import OpenIDSchema
from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import RefreshAccessTokenRequest
from oic.oic.message import RegistrationRequest
from oic.oic.message import RegistrationResponse

from .access_token import extract_bearer_token_from_http_request
from .client_authentication import verify_client_authentication
from .exceptions import AuthorizationError
from .exceptions import InvalidAccessToken
from .exceptions import InvalidTokenRequest
from .exceptions import InvalidAuthorizationCode
from .request_validator import authorization_request_verify
from .request_validator import client_id_is_known
from .request_validator import client_preferences_match_provider_capabilities
from .request_validator import redirect_uri_is_in_registered_redirect_uris
from .request_validator import registration_request_verify
from .request_validator import requested_scope_is_supported
from .request_validator import response_type_is_in_registered_response_types
from .request_validator import userinfo_claims_only_specified_when_access_token_is_issued
from .util import find_common_values

logger = logging.getLogger(__name__)


class Provider(object):
    def __init__(self, signing_key, configuration_information, authz_state, clients, userinfo, *,
                 id_token_lifetime=3600, extra_scopes=None):
        # type: (jwkest.jwk.Key, Dict[str, Union[str, Sequence[str]]], se_leg_op.authz_state.AuthorizationState,
        #        Mapping[str, Mapping[str, Any]], se_leg_op.userinfo.Userinfo, int) -> None
        """
        Creates a new provider instance.
        :param configuration_information: see
            <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">
            "OpenID Connect Discovery 1.0", Section 3</a>
        :param clients: see <a href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata">
            "OpenID Connect Dynamic Client Registration 1.0", Section 2</a>
        :param userinfo: read-only interface for user info
        :param id_token_lifetime: how long the signed ID Tokens should be valid (in seconds), defaults to 1 hour
        """
        self.signing_key = signing_key
        self.configuration_information = ProviderConfigurationResponse(**configuration_information)
        if 'subject_types_supported' not in configuration_information:
            self.configuration_information['subject_types_supported'] = ['pairwise']
        if 'id_token_signing_alg_values_supported' not in configuration_information:
            self.configuration_information['id_token_signing_alg_values_supported'] = ['RS256']
        if 'scopes_supported' not in configuration_information:
            self.configuration_information['scopes_supported'] = ['openid']
        if 'response_types_supported' not in configuration_information:
            self.configuration_information['response_types_supported'] = ['code', 'id_token', 'token id_token']

        self.extra_scopes = {} if extra_scopes is None else extra_scopes
        _scopes = self.configuration_information['scopes_supported']
        _scopes.extend(self.extra_scopes.keys())
        self.configuration_information['scopes_supported'] = list(set(_scopes))

        self.configuration_information.verify()

        self.authz_state = authz_state
        self.clients = clients
        self.userinfo = userinfo
        self.id_token_lifetime = id_token_lifetime

        self.authentication_request_validators = []  # type: List[Callable[[oic.oic.message.AuthorizationRequest], Boolean]]
        self.authentication_request_validators.append(authorization_request_verify)
        self.authentication_request_validators.append(
            functools.partial(client_id_is_known, self))
        self.authentication_request_validators.append(
            functools.partial(redirect_uri_is_in_registered_redirect_uris, self))
        self.authentication_request_validators.append(
            functools.partial(response_type_is_in_registered_response_types, self))
        self.authentication_request_validators.append(userinfo_claims_only_specified_when_access_token_is_issued)
        self.authentication_request_validators.append(functools.partial(requested_scope_is_supported, self))

        self.registration_request_validators = []  # type: List[Callable[[oic.oic.message.RegistrationRequest], Boolean]]
        self.registration_request_validators.append(registration_request_verify)
        self.registration_request_validators.append(
            functools.partial(client_preferences_match_provider_capabilities, self))

    @property
    def provider_configuration(self):
        """
        The provider configuration information.
        """
        return copy.deepcopy(self.configuration_information)

    @property
    def jwks(self):
        """
        All keys published by the provider as JSON Web Key Set.
        """

        keys = [self.signing_key.serialize()]
        return {'keys': keys}

    def parse_authentication_request(self, request_body, http_headers=None):
        # type: (str, Optional[Mapping[str, str]]) -> oic.oic.message.AuthorizationRequest
        """
        Parses and verifies an authentication request.

        :param request_body: urlencoded authentication request
        :param http_headers: http headers
        """

        auth_req = AuthorizationRequest().deserialize(request_body)

        for validator in self.authentication_request_validators:
            validator(auth_req)

        logger.debug('parsed authentication_request: %s', auth_req)
        return auth_req

    def authorize(self, authentication_request,  # type: oic.oic.message.AuthorizationRequest
                  user_id,  # type: str
                  extra_id_token_claims=None
                  # type: Optional[Union[Mapping[str, Union[str, List[str]]], Callable[[str, str], Mapping[str, Union[str, List[str]]]]]
                  ):
        # type: (...) -> oic.oic.message.AuthorizationResponse
        """
        Creates an Authentication Response for the specified authentication request and local identifier of the
        authenticated user.
        """
        custom_sub = self.userinfo[user_id].get('sub')
        if custom_sub:
            self.authz_state.subject_identifiers[user_id] = {'public': custom_sub}
            sub = custom_sub
        else:
            sub = self._create_subject_identifier(user_id, authentication_request['client_id'],
                                                  authentication_request['redirect_uri'])

        self._check_subject_identifier_matches_requested(authentication_request, sub)
        response = AuthorizationResponse()

        authz_code = None
        if 'code' in authentication_request['response_type']:
            authz_code = self.authz_state.create_authorization_code(authentication_request, sub)
            response['code'] = authz_code

        access_token_value = None
        if 'token' in authentication_request['response_type']:
            access_token = self.authz_state.create_access_token(authentication_request, sub)
            access_token_value = access_token.value
            self._add_access_token_to_response(response, access_token)

        if 'id_token' in authentication_request['response_type']:
            if extra_id_token_claims is None:
                extra_id_token_claims = {}
            elif callable(extra_id_token_claims):
                extra_id_token_claims = extra_id_token_claims(user_id, authentication_request['client_id'])

            requested_claims = self._get_requested_claims_in(authentication_request, 'id_token')
            if len(authentication_request['response_type']) == 1:
                # only id token is issued -> no way of doing userinfo request, so include all claims in ID Token,
                # even those requested by the scope parameter
                requested_claims.update(
                    scope2claims(
                        authentication_request['scope'], extra_scope_dict=self.extra_scopes
                    )
                )

            user_claims = self.userinfo.get_claims_for(user_id, requested_claims)
            response['id_token'] = self._create_signed_id_token(authentication_request['client_id'], sub,
                                                                user_claims,
                                                                authentication_request.get('nonce'),
                                                                authz_code, access_token_value, extra_id_token_claims)
            logger.debug('issued id_token=%s from requested_claims=%s userinfo=%s extra_claims=%s',
                         response['id_token'], requested_claims, user_claims, extra_id_token_claims)

        if 'state' in authentication_request:
            response['state'] = authentication_request['state']
        return response

    def _add_access_token_to_response(self, response, access_token):
        # type: (oic.message.AccessTokenResponse, se_leg_op.access_token.AccessToken) -> None
        """
        Adds the Access Token and the associated parameters to the Token Response.
        """
        response['access_token'] = access_token.value
        response['token_type'] = access_token.type
        response['expires_in'] = access_token.expires_in

    def _create_subject_identifier(self, user_id, client_id, redirect_uri):
        # type (str, str, str) -> str
        """
        Creates a subject identifier for the specified client and user
        see <a href="http://openid.net/specs/openid-connect-core-1_0.html#Terminology">
        "OpenID Connect Core 1.0", Section 1.2</a>.
        :param user_id: local user identifier
        :param client_id: which client to generate a subject identifier for
        :param redirect_uri: the clients' redirect_uri
        :return: a subject identifier for the user intended for client who made the authentication request
        """
        supported_subject_types = self.configuration_information['subject_types_supported'][0]
        subject_type = self.clients[client_id].get('subject_type', supported_subject_types)
        sector_identifier = urlparse(redirect_uri).netloc
        return self.authz_state.get_subject_identifier(subject_type, user_id, sector_identifier)

    def _get_requested_claims_in(self, authentication_request, response_method):
        # type (oic.oic.message.AuthorizationRequest, str) -> Mapping[str, Optional[Mapping[str, Union[str, List[str]]]]
        """
        Parses any claims requested using the 'claims' request parameter, see
        <a href="http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter">
        "OpenID Connect Core 1.0", Section 5.5</a>.
        :param authentication_request: the authentication request
        :param response_method: 'id_token' or 'userinfo'
        """
        if response_method != 'id_token' and response_method != 'userinfo':
            raise ValueError('response_method must be \'id_token\' or \'userinfo\'')

        requested_claims = {}

        if 'claims' in authentication_request and response_method in authentication_request['claims']:
            requested_claims.update(authentication_request['claims'][response_method])
        return requested_claims

    def _create_signed_id_token(self,
                                client_id,  # type: str
                                sub,  # type: str
                                user_claims=None,  # type: Optional[Mapping[str, Union[str, List[str]]]]
                                nonce=None,  # type: Optional[str]
                                authorization_code=None,  # type: Optional[str]
                                access_token_value=None,  # type: Optional[str]
                                extra_id_token_claims=None):  # type: Optional[Mappings[str, Union[str, List[str]]]]
        # type: (...) -> str
        """
        Creates a signed ID Token.
        :param client_id: who the ID Token is intended for
        :param sub: who the ID Token is regarding
        :param user_claims: any claims about the user to be included
        :param nonce: nonce from the authentication request
        :param authorization_code: the authorization code issued together with this ID Token
        :param access_token_value: the access token issued together with this ID Token
        :param extra_id_token_claims: any extra claims that should be included in the ID Token
        :return: a JWS, containing the ID Token as payload
        """

        alg = self.clients[client_id].get('id_token_signed_response_alg',
                                          self.configuration_information['id_token_signing_alg_values_supported'][0])
        args = {}

        hash_alg = 'HS{}'.format(alg[-3:])
        if authorization_code:
            args['c_hash'] = jws.left_hash(authorization_code.encode('utf-8'), hash_alg)
        if access_token_value:
            args['at_hash'] = jws.left_hash(access_token_value.encode('utf-8'), hash_alg)

        if user_claims:
            args.update(user_claims)

        if extra_id_token_claims:
            args.update(extra_id_token_claims)

        id_token = IdToken(iss=self.configuration_information['issuer'],
                           sub=sub,
                           aud=client_id,
                           iat=int(time.time()),
                           exp=int(time.time()) + self.id_token_lifetime,
                           **args)

        if nonce:
            id_token['nonce'] = nonce

        logger.debug('signed id_token with kid=%s using alg=%s', self.signing_key, alg)
        return id_token.to_jwt([self.signing_key], alg)

    def _check_subject_identifier_matches_requested(self, authentication_request, sub):
        # type (oic.message.AuthorizationRequest, str) -> None
        """
        Verifies the subject identifier against any requested subject identifier using the claims request parameter.
        :param authentication_request: authentication request
        :param sub: subject identifier
        :raise AuthorizationError: if the subject identifier does not match the requested one
        """
        if 'claims' in authentication_request:
            requested_id_token_sub = authentication_request['claims'].get('id_token', {}).get('sub')
            requested_userinfo_sub = authentication_request['claims'].get('userinfo', {}).get('sub')
            if requested_id_token_sub and requested_userinfo_sub and requested_id_token_sub != requested_userinfo_sub:
                raise AuthorizationError('Requested different subject identifier for IDToken and userinfo: {} != {}'
                                         .format(requested_id_token_sub, requested_userinfo_sub))

            requested_sub = requested_id_token_sub or requested_userinfo_sub
            if requested_sub and sub != requested_sub:
                raise AuthorizationError('Requested subject identifier \'{}\' could not be matched'
                                         .format(requested_sub))

    def handle_token_request(self, request_body,  # type: str
                             http_headers=None,  # type: Optional[Mapping[str, str]]
                             extra_id_token_claims=None
                             # type: Optional[Union[Mapping[str, Union[str, List[str]]], Callable[[str, str], Mapping[str, Union[str, List[str]]]]]
                             ):
        # type: (...) -> oic.oic.message.AccessTokenResponse
        """
        Handles a token request, either for exchanging an authorization code or using a refresh token.
        :param request_body: urlencoded token request
        :param http_headers: http headers
        :param extra_id_token_claims: extra claims to include in the signed ID Token
        """

        token_request = self._verify_client_authentication(request_body, http_headers)

        if 'grant_type' not in token_request:
            raise InvalidTokenRequest('grant_type missing', token_request)
        elif token_request['grant_type'] == 'authorization_code':
            return self._do_code_exchange(token_request, extra_id_token_claims)
        elif token_request['grant_type'] == 'refresh_token':
            return self._do_token_refresh(token_request)

        raise InvalidTokenRequest('grant_type \'{}\' unknown'.format(token_request['grant_type']), token_request,
                                  oauth_error='unsupported_grant_type')

    def _do_code_exchange(self, request,  # type: Dict[str, str]
                          extra_id_token_claims=None
                          # type: Optional[Union[Mapping[str, Union[str, List[str]]], Callable[[str, str], Mapping[str, Union[str, List[str]]]]]
                          ):
        # type: (...) -> oic.message.AccessTokenResponse
        """
        Handles a token request for exchanging an authorization code for an access token
        (grant_type=authorization_code).
        :param request: parsed http request parameters
        :param extra_id_token_claims: any extra parameters to include in the signed ID Token, either as a dict-like
            object or as a callable object accepting the local user identifier and client identifier which returns
            any extra claims which might depend on the user id and/or client id.
        :return: a token response containing a signed ID Token, an Access Token, and a Refresh Token
        :raise InvalidTokenRequest: if the token request is invalid
        """
        token_request = AccessTokenRequest().from_dict(request)
        try:
            token_request.verify()
        except MessageException as e:
            raise InvalidTokenRequest(str(e), token_request) from e

        authentication_request = self.authz_state.get_authorization_request_for_code(token_request['code'])

        if token_request['client_id'] != authentication_request['client_id']:
            logger.info('Authorization code \'%s\' belonging to \'%s\' was used by \'%s\'',
                        token_request['code'], authentication_request['client_id'], token_request['client_id'])
            raise InvalidAuthorizationCode('{} unknown'.format(token_request['code']))
        if token_request['redirect_uri'] != authentication_request['redirect_uri']:
            raise InvalidTokenRequest('Invalid redirect_uri: {} != {}'.format(token_request['redirect_uri'],
                                                                              authentication_request['redirect_uri']),
                                      token_request)

        sub = self.authz_state.get_subject_identifier_for_code(token_request['code'])
        user_id = self.authz_state.get_user_id_for_subject_identifier(sub)

        response = AccessTokenResponse()

        access_token = self.authz_state.exchange_code_for_token(token_request['code'])
        self._add_access_token_to_response(response, access_token)
        refresh_token = self.authz_state.create_refresh_token(access_token.value)
        if refresh_token is not None:
            response['refresh_token'] = refresh_token

        if extra_id_token_claims is None:
            extra_id_token_claims = {}
        elif callable(extra_id_token_claims):
            extra_id_token_claims = extra_id_token_claims(user_id, authentication_request['client_id'])
        requested_claims = self._get_requested_claims_in(authentication_request, 'id_token')
        user_claims = self.userinfo.get_claims_for(user_id, requested_claims)
        response['id_token'] = self._create_signed_id_token(authentication_request['client_id'], sub,
                                                            user_claims,
                                                            authentication_request.get('nonce'),
                                                            None, access_token.value,
                                                            extra_id_token_claims)
        logger.debug('issued id_token=%s from requested_claims=%s userinfo=%s extra_claims=%s',
                     response['id_token'], requested_claims, user_claims, extra_id_token_claims)

        return response

    def _do_token_refresh(self, request):
        # type: (Mapping[str, str]) -> oic.oic.message.AccessTokenResponse
        """
        Handles a token request for refreshing an access token (grant_type=refresh_token).
        :param request: parsed http request parameters
        :return: a token response containing a new Access Token and possibly a new Refresh Token
        :raise InvalidTokenRequest: if the token request is invalid
        """
        token_request = RefreshAccessTokenRequest().from_dict(request)
        try:
            token_request.verify()
        except MessageException as e:
            raise InvalidTokenRequest(str(e), token_request) from e

        response = AccessTokenResponse()

        access_token, refresh_token = self.authz_state.use_refresh_token(token_request['refresh_token'],
                                                                         scope=token_request.get('scope'))
        self._add_access_token_to_response(response, access_token)
        if refresh_token:
            response['refresh_token'] = refresh_token

        return response

    def _verify_client_authentication(self, request_body, http_headers=None):
        # type (str, Optional[Mapping[str, str]] -> Mapping[str, str]
        """
        Verifies the client authentication.
        :param request_body: urlencoded token request
        :param http_headers:
        :return: The parsed request body.
        """
        if http_headers is None:
            http_headers = {}
        token_request = dict(parse_qsl(request_body))
        token_request['client_id']  = verify_client_authentication(self.clients, token_request, http_headers.get('Authorization'))
        return token_request

    def handle_userinfo_request(self, request=None, http_headers=None):
        # type: (Optional[str], Optional[Mapping[str, str]]) -> oic.oic.message.OpenIDSchema
        """
        Handles a userinfo request.
        :param request: urlencoded request (either query string or POST body)
        :param http_headers: http headers
        """
        if http_headers is None:
            http_headers = {}
        userinfo_request = dict(parse_qsl(request))
        bearer_token = extract_bearer_token_from_http_request(userinfo_request, http_headers.get('Authorization'))

        introspection = self.authz_state.introspect_access_token(bearer_token)
        if not introspection['active']:
            raise InvalidAccessToken('The access token has expired')
        scopes = introspection['scope'].split()
        user_id = self.authz_state.get_user_id_for_subject_identifier(introspection['sub'])

        requested_claims = scope2claims(scopes, extra_scope_dict=self.extra_scopes)
        authentication_request = self.authz_state.get_authorization_request_for_access_token(bearer_token)
        requested_claims.update(self._get_requested_claims_in(authentication_request, 'userinfo'))
        user_claims = self.userinfo.get_claims_for(user_id, requested_claims)

        user_claims.setdefault('sub', introspection['sub'])
        response = OpenIDSchema(**user_claims)
        logger.debug('userinfo=%s from requested_claims=%s userinfo=%s',
                     response, requested_claims, user_claims)
        return response

    def _issue_new_client(self):
        # create unique client id
        client_id = rndstr(12)
        while client_id in self.clients:
            client_id = rndstr(12)
        # create random secret
        client_secret = uuid.uuid4().hex

        return client_id, client_secret

    def match_client_preferences_with_provider_capabilities(self, client_preferences):
        # type: (oic.message.RegistrationRequest) -> Mapping[str, Union[str, List[str]]]
        """
        Match as many as of the client preferences as possible.
        :param client_preferences: requested preferences from client registration request
        :return: the matched preferences selected by the provider
        """
        matched_prefs = client_preferences.to_dict()
        for pref in ['response_types', 'default_acr_values']:
            if pref not in client_preferences:
                continue

            capability = PREFERENCE2PROVIDER[pref]
            # only preserve the common values
            matched_values = find_common_values(client_preferences[pref], self.configuration_information[capability])
            # deal with space separated values
            matched_prefs[pref] = [' '.join(v) for v in matched_values]

        return matched_prefs

    def handle_client_registration_request(self, request, http_headers=None):
        # type: (Optional[str], Optional[Mapping[str, str]]) -> oic.oic.message.RegistrationResponse
        """
        Handles a client registration request.
        :param request: JSON request from POST body
        :param http_headers: http headers
        """
        registration_req = RegistrationRequest().deserialize(request, 'json')

        for validator in self.registration_request_validators:
            validator(registration_req)
        logger.debug('parsed authentication_request: %s', registration_req)

        client_id, client_secret = self._issue_new_client()
        credentials = {
            'client_id': client_id,
            'client_id_issued_at': int(time.time()),
            'client_secret': client_secret,
            'client_secret_expires_at': 0  # never expires
        }

        response_params = self.match_client_preferences_with_provider_capabilities(registration_req)
        response_params.update(credentials)
        self.clients[client_id] = copy.deepcopy(response_params)

        registration_resp = RegistrationResponse(**response_params)
        logger.debug('registration_resp=%s from registration_req=%s', registration_resp, registration_req)
        return registration_resp

    def logout_user(self, subject_identifier=None, end_session_request=None):
        # type: (Optional[str], Optional[oic.oic.message.EndSessionRequest]) -> None
        if not end_session_request:
            end_session_request = EndSessionRequest()
        if 'id_token_hint' in end_session_request:
            id_token = IdToken().from_jwt(end_session_request['id_token_hint'], key=[self.signing_key])
            subject_identifier = id_token['sub']

        self.authz_state.delete_state_for_subject_identifier(subject_identifier)

    def do_post_logout_redirect(self, end_session_request):
        # type: (oic.oic.message.EndSessionRequest) -> oic.oic.message.EndSessionResponse
        if 'post_logout_redirect_uri' not in end_session_request:
            return None

        client_id = None
        if 'id_token_hint' in end_session_request:
            id_token = IdToken().from_jwt(end_session_request['id_token_hint'], key=[self.signing_key])
            client_id = id_token['aud'][0]

        if 'post_logout_redirect_uri' in end_session_request:
            if not client_id:
                return None
            if not end_session_request['post_logout_redirect_uri'] in self.clients[client_id].get(
                    'post_logout_redirect_uris', []):
                return None

        end_session_response = EndSessionResponse()
        if 'state' in end_session_request:
            end_session_response['state'] = end_session_request['state']

        return end_session_response.request(end_session_request['post_logout_redirect_uri'])
