from flask.app import Flask
from flask.helpers import url_for
from jwkest.jwk import RSAKey, rsa_load

from pyop.authz_state import AuthorizationState
from pyop.provider import Provider
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo


def init_oidc_provider(app):
    with app.app_context():
        issuer = url_for('oidc_provider.index')[:-1]
        authentication_endpoint = url_for('oidc_provider.authentication_endpoint')
        jwks_uri = url_for('oidc_provider.jwks_uri')
        token_endpoint = url_for('oidc_provider.token_endpoint')
        userinfo_endpoint = url_for('oidc_provider.userinfo_endpoint')
        registration_endpoint = url_for('oidc_provider.registration_endpoint')
        end_session_endpoint = url_for('oidc_provider.end_session_endpoint')

    configuration_information = {
        'issuer': issuer,
        'authorization_endpoint': authentication_endpoint,
        'jwks_uri': jwks_uri,
        'token_endpoint': token_endpoint,
        'userinfo_endpoint': userinfo_endpoint,
        'registration_endpoint': registration_endpoint,
        'end_session_endpoint': end_session_endpoint,
        'scopes_supported': ['openid', 'profile'],
        'response_types_supported': ['code', 'code id_token', 'code token',
                                     'code id_token token'],  # code and hybrid
        'response_modes_supported': ['query', 'fragment'],
        'grant_types_supported': ['authorization_code', 'implicit'],
        'subject_types_supported': ['pairwise'],
        'token_endpoint_auth_methods_supported': ['client_secret_basic',
                                                  'client_secret_post'],
        'claims_parameter_supported': True
    }

    userinfo_db = Userinfo(app.users)
    signing_key = RSAKey(key=rsa_load('signing_key.pem'), alg='RS256')
    provider = Provider(signing_key, configuration_information,
                        AuthorizationState(HashBasedSubjectIdentifierFactory(
                            app.config['SUBJECT_ID_HASH_SALT'])),
                        {}, userinfo_db)

    return provider


def oidc_provider_init_app(name=None):
    name = name or __name__
    app = Flask(name)
    app.config.from_pyfile('application.cfg')

    app.users = {'test_user': {'name': 'Testing Name'}}

    from .views import oidc_provider_views
    app.register_blueprint(oidc_provider_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.provider = init_oidc_provider(app)

    return app
