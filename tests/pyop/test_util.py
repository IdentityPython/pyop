import pytest
from oic.oic.message import AuthorizationRequest

from pyop.util import should_fragment_encode


class TestShouldFragmentEncode(object):
    @pytest.mark.parametrize('response_type, expected', [
        ('code', False),
        ('id_token', True),
        ('id_token token', True),
        ('code id_token', True),
        ('code token', True),
        ('code id_token token', True),
    ])
    def test_by_response_type(self, response_type, expected):
        auth_req = {'response_type': response_type}
        assert should_fragment_encode(AuthorizationRequest(**auth_req)) is expected
