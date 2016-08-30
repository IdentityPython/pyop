class Userinfo(object):
    """
    Wrapper providing a read-only interface for a database containing user info.

    The backing database must use a local identifier as key, and all userinfo that should be returned in OpenID
    Connect ID Tokens or Userinfo Responses must follow the format of OpenID Connect standard claims, see
    <a href="http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">
    "OpenID Connect Core 1.0", Section 5.1</a>
    """

    def __init__(self, db):
        # type: (Mapping[str, Union[str, List[str]]]) -> None
        self._db = db

    def __getitem__(self, item):
        return self._db[item]

    def __contains__(self, item):
        return item in self._db

    def get_claims_for(self, user_id, requested_claims):
        # type: (str, Mapping[str, Optional[Mapping[str, Union[str, List[str]]]]) -> Dict[str, Union[str, List[str]]]
        """
        Filter the userinfo based on which claims where requested.
        :param user_id: user identifier
        :param requested_claims: see <a href="http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter">
            "OpenID Connect Core 1.0", Section 5.5</a> for structure
        :return: All requested claims available from the userinfo.
        """

        userinfo = self._db[user_id]
        claims = {claim: userinfo[claim] for claim in requested_claims if claim in userinfo}
        return claims
