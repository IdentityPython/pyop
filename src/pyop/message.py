from oic.oauth2.message import SINGLE_OPTIONAL_STRING
from oic.oic import message

class AccessTokenRequest(message.AccessTokenRequest):
    c_param = message.AccessTokenRequest.c_param.copy()
    c_param.update(
        {
            'code_verifier': SINGLE_OPTIONAL_STRING
        }
    )

class AuthorizationRequest(message.AuthorizationRequest):
    c_param = message.AuthorizationRequest.c_param.copy()
    c_param.update(
        {
            'code_challenge': SINGLE_OPTIONAL_STRING,
            'code_challenge_method': SINGLE_OPTIONAL_STRING
        }
    )

    c_allowed_values = message.AuthorizationRequest.c_allowed_values.copy()
    c_allowed_values.update(
        {
        "code_challenge_method": [
                "plain",
                "S256"
            ]
        }
    )
