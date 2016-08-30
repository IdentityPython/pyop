import hashlib


class SubjectIdentifierFactory(object):
    """
    Interface for implementation of an algorithm for creating pairwise subject identifiers, see
    <a href="http://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg">
    "OpenID Connect Core 1.0", Section 8.1</a>.
    """

    def create_public_identifier(self, user_id):
        # type: (str) -> str
        raise NotImplementedError()

    def create_pairwise_identifier(self, user_id, sector_identifier):
        # type: (str, str) -> str
        raise NotImplementedError()


class HashBasedSubjectIdentifierFactory(object):
    """
    Implements a hash based algorithm for creating a pairwise subject identifier.
    """

    def __init__(self, hash_salt):
        # type: (str) -> None
        self.hash_salt = hash_salt

    def create_public_identifier(self, user_id):
        return self._hash(user_id)

    def create_pairwise_identifier(self, user_id, sector_identifier):
        return self._hash(sector_identifier + user_id)

    def _hash(self, data):
        # type: (str) -> str
        hash_input = data + self.hash_salt
        return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
