import logging

from example.app import oidc_provider_init_app

name = 'oidc_provider'
app = oidc_provider_init_app(name)
logging.basicConfig(level=logging.DEBUG)
