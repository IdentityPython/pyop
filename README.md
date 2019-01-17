# pyOP
[![Build Status](https://travis-ci.org/IdentityPython/pyop.svg)](https://travis-ci.org/IdentityPython/pyop)
[![PyPI](https://img.shields.io/pypi/v/pyop.svg)](https://pypi.python.org/pypi/pyop)


OpenID Connect Provider (OP) library in Python.
Uses [pyoidc](https://github.com/rohe/pyoidc/) and
[pyjwkest](https://github.com/rohe/pyjwkest).

# Provider implementations using pyOP
* [se-leg-op](https://github.com/SUNET/se-leg-op)
* [SATOSA OIDC frontend](https://github.com/its-dirg/SATOSA/blob/master/src/satosa/frontends/openid_connect.py)
* [local example](example/views.py)

# Introduction

pyOP is a high-level library intended to be usable in any web server application.
By only providing the core functionality for OpenID Connect the application can freely choose to implement any kind of
authentication mechanisms, while pyOP provides a simple interface for the OpenID Connect messages to send back to
clients.

## OpenID Connect support
* [Dynamic Provider Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
* [Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html)
* [Core](http://openid.net/specs/openid-connect-core-1_0.html)
    * [Authorization Code Flow](http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps)
    * [Implicit Flow](http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth)
    * [Hybrid Flow](http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth)
    * Claims
        * [Requesting Claims using Scope Values](http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
        * [Claims Request Parameter](http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter)
* Crypto support
    * Currently only supports issuing signed ID Tokens

# Configuration
The provider instance can be configured through the provider configuration information. In the following example, a
provider instance is initiated to use a MongoDB instance as its backend storage:

```python
from jwkest.jwk import rsa_load, RSAKey

from pyop.authz_state import AuthorizationState
from pyop.provider import Provider
from pyop.storage import MongoWrapper
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo

signing_key = RSAKey(key=rsa_load('signing_key.pem'), use='sig', alg='RS256')
configuration_information = {
    'issuer': 'https://example.com',
    'authorization_endpoint': 'https://example.com/authorization',
    'token_endpoint': 'https://example.com/token',
    'userinfo_endpoint': 'https://example.com/userinfo',
    'registration_endpoint': 'https://example.com/registration',
    'response_types_supported': ['code', 'id_token token'],
    'id_token_signing_alg_values_supported': [signing_key.alg],
    'response_modes_supported': ['fragment', 'query'],
    'subject_types_supported': ['public', 'pairwise'],
    'grant_types_supported': ['authorization_code', 'implicit'],
    'claim_types_supported': ['normal'],
    'claims_parameter_supported': True,
    'claims_supported': ['sub', 'name', 'given_name', 'family_name'],
    'request_parameter_supported': False,
    'request_uri_parameter_supported': False,
    'scopes_supported': ['openid', 'profile']
}

subject_id_factory = HashBasedSubjectIdentifierFactory(sub_hash_salt)
authz_state = AuthorizationState(subject_id_factory,
                                 MongoWrapper(db_uri, 'provider', 'authz_codes'),
                                 MongoWrapper(db_uri, 'provider', 'access_tokens'),
                                 MongoWrapper(db_uri, 'provider', 'refresh_tokens'),
                                 MongoWrapper(db_uri, 'provider', 'subject_identifiers'))
client_db = MongoWrapper(db_uri, 'provider', 'clients')
user_db = MongoWrapper(db_uri, 'provider', 'users')
provider = Provider(signing_key, configuration_information, authz_state, client_db, Userinfo(user_db))
```

where `db_uri` is the [MongoDB connection URI](https://docs.mongodb.com/manual/reference/connection-string/) and
`sub_hash_salt` is a secret string to use as a salt when creating hash based subject identifiers.

## Token lifetimes
The ID token lifetime (in seconds) can be supplied to the `Provider` constructor with `id_token_lifetime`, e.g.:

```python
Provider(..., id_token_lifetime=600)
```
If not specified it will default to 1 hour.

The lifetime of authorization codes, access tokens, and refresh tokens is configured in the `AuthorizationState`, e.g.:

```python
AuthorizationState(..., authorization_code_lifetime=300, access_token_lifetime=60*60*24,
                   refresh_token_lifetime=60*60*24*365, refresh_token_threshold=None)
```

If not specified the lifetimes defaults to the following values:
* Authorization codes are valid for 10 minutes.
* Access tokens are valid for 1 hour.
* Refresh tokens are not issued.

To make sure refresh tokens are issued in response to code exchange token requests, specify a
`refresh_token_lifetime` > 0.
To make sure refresh tokens are renewed if they are close to expiry in response to refresh token requests,
specify a `refresh_token_threshold` > 0.

# Dynamic discovery: Provider Configuration Information
To publish the provider configuration information at an endpoint, use `Provider.provider_configuration`.

The following example illustrates the high-level idea:

```python
@app.route('/.well-known/openid-configuration')
def provider_config():
    return HTTPResponse(provider.provider_configuration.to_json(), content_type="application/json")
```

# Authorization endpoint
An incoming authentication request can be validated by the provider using `Provider.parse_authentication_request`.
If the request is valid, it should be stored and associated with the current user session to be able to retrieve it
when the end-user authentication is completed.

```python
from pyop.exceptions import InvalidAuthenticationRequest

@app.route('/authorization')
def authorization_endpoints(request):
    try:
        authn_req = provider.parse_authentication_request(request)
    except InvalidAuthenticationRequest as e:
        error_url = e.to_error_url()

        if error_url:
            return HTTPResponse(error_url, status=303)
        else:
            return HTTPResponse("Something went wrong: {}".format(str(e)), status=400)

    session['authn_req'] = authn_req.to_dict()
    // TODO initiate end-user authentication
```

When the authentication is completed by the user, the provider must be notified to make an authentication response
to the client's 'redirect_uri'. This is done with `Provider.authorize`, where the local user id supplied must exist
in the user database supplied on initialization. When using the included `MongoWrapper`, no mapping is done between
user data and OpenID Connect claim names. Hence the underlying data source must contain the user information under the
same names as the [standard claims of OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).

```python
from oic.oic.message import AuthorizationRequest

from pyop.util import should_fragment_encode

authn_req = session['authn_req']
authn_response = provider.authorize(AuthorizationRequest().from_dict(authn_req), user_id)
return_url = authn_response.request(authn_req['redirect_uri'], should_fragment_encode(authn_req))

return HTTPResponse(return_url, status=303)
```

## Authentication request validation
The provider instance is by default configured to validate authentication requests according to the OpenID Connect
Core specification. If you need to add additional custom validation of authentication requests, that's possible by
adding such validation functions to the list of authentication request validators.

In this example an additional validator that checks that the 'nonce' parameter is included in all requests is added:

```python
from pyop.exceptions import InvalidAuthenticationRequest

def request_contains_nonce(authentication_request):
    if 'nonce' not in authentication_request:
        raise InvalidAuthenticationRequest('The request does not contain a nonce', authentication_request,
                                           oauth_error='invalid_request')

provider.authentication_request_validators.append(request_contains_nonce)
```

# Token endpoint
An incoming token request is processed by `Provider.handle_token_request`. It will validate the request and issue all
necessary tokens (access token and possibly refresh token)

```python
from oic.oic.message import TokenErrorResponse

from pyop.exceptions import InvalidClientAuthentication
from pyop.exceptions import OAuthError

@app.route('/token', methods=['POST', 'GET'])
def token_endpoint(request):
    try:
        token_response = provider.handle_token_request(request.get_data().decode('utf-8'),
                                                       request.headers)
        return HTTPResponse(token_response.to_json(), content_type='application/json')
    except InvalidClientAuthentication as e:
        error_resp = TokenErrorResponse(error='invalid_client', error_description=str(e))
        http_response = HTTPResponse(error_resp.to_json(), status=401, content_type='application/json')
        http_response.headers['WWW-Authenticate'] = 'Basic'
        return http_response
    except OAuthError as e:
        error_resp = TokenErrorResponse(error=e.oauth_error, error_description=str(e))
        return HTTPResponse(error_resp.to_json(), status=400, content_type='application/json')
```


# Userinfo endpoint
An incoming userinfo request is processed by `Provider.handle_userinfo_request`. It will validate the request and return
all requested userinfo.

```python
from oic.oic.message import UserInfoErrorResponse

from pyop.access_token import AccessToken
from pyop.exceptions import BearerTokenError
from pyop.exceptions import InvalidAccessToken

@app.route('/userinfo', methods=['GET', 'POST'])
def userinfo_endpoint(request):
    try:
        response = provider.handle_userinfo_request(request.get_data().decode('utf-8'),
                                                    request.headers)
        return HTTPResponse(response.to_json(), content_type='application/json')
    except (BearerTokenError, InvalidAccessToken) as e:
        error_resp = UserInfoErrorResponse(error='invalid_token', error_description=str(e))
        http_response = HTTPResponse(error_resp.to_json(), status=401, content_type='application/json')
        http_response.headers['WWW-Authenticate'] = AccessToken.BEARER_TOKEN_TYPE
        return http_response
```


# Dynamic client registration

An incoming client registration request is process by `Provider.handle_client_registration_request`. It will validate the request,
store the registered metadata and issue new client credentials.

```python
from pyop.exceptions import InvalidClientRegistrationRequest

@app.route('/registration', methods=['POST'])
def registration_endpoint(request):
    try:
        response = provider.handle_client_registration_request(request.get_data().decode('utf-8'))
        return HTTPResponse(response.to_json(), status=201, content_type='application/json')
    except InvalidClientRegistrationRequest as e:
        return HTTPResponse(e.to_json(), status=400, content_type='application/json')
```

## Registration request validation
The provider instance is by default configured to validate registration requests according to the OpenID Connect
Dynamic Registration specification. If you need to add additional custom validation of registration requests, that's
possible by adding such validation functions to the list of registration request validators.

In this example an additional validator that checks that the 'software_statement' parameter is included in all requests
is added:

```python
def request_contains_software_statement(registration_request):
    if 'software_statement' not in registration_request:
        raise InvalidClientRegistrationRequest('The request does not contain a software_statement', registration_request,
                                               oauth_error='invalid_request')

provider.registration_request_validators.append(request_contains_software_statement)
```

# User logout

RP-initiated logout, as described in [Section 5 of OpenID Connect Session Management](http://openid.net/specs/openid-connect-session-1_0.html#RPLogout)
is supported. The parsed request should be passed to `Provider.logout_user` together with any known subject identifier
for the user, and then `Provider.do_post_logout_redirect` should be called do obey any valid `post_logout_redirect_uri`
included in the request.

```python
from oic.oic.message import EndSessionRequest

from pyop.exceptions import InvalidSubjectIdentifier

@app.route('/logout')
def end_session_endpoint(request):
    end_session_request = EndSessionRequest().deserialize(request.get_data().decode('utf-8'))

    try:
        provider.logout_user(session.get('sub'), end_session_request)
    except InvalidSubjectIdentifier as e:
        return HTTPResponse('Logout unsuccessful!', content_type='text/html', status=400)

    # TODO automagic logout, should ask user first!
    redirect_url = provider.do_post_logout_redirect(end_session_request)
    if redirect_url:
        return HTTPResponse(redirect_url, status=303)

    return HTTPResponse('Logout successful!', content_type='text/html')
```

# Exceptions
All exceptions, except `AuthorizationError`, inherits from `ValueError`. However it might be necessary to distinguish
between them to send the correct error message back to the client according to the OpenID Connect specifications.

All OAuth errors contain the OAuth error code in `OAuthError.oauth_error`, together with the error description as the
message of the exception (accessed by `str(exception)`).
