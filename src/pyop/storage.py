# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
import copy
import json
import logging
from datetime import datetime
from urllib.parse import urlparse
from urllib.parse import parse_qs

from .crypto import _AESCipher


logger = logging.getLogger(__name__)


try:
    import pymongo
except ImportError:
    _has_pymongo = False
else:
    _has_pymongo = True

try:
    from redis.client import Redis
except ImportError:
    _has_redis = False
else:
    _has_redis = True


class StorageBase(ABC):
    _ttl = None

    @abstractmethod
    def __setitem__(self, key, value):
        pass

    @abstractmethod
    def pack(self, value):
        pass

    @abstractmethod
    def __getitem__(self, key):
        pass

    @abstractmethod
    def __delitem__(self, key):
        pass

    @abstractmethod
    def __contains__(self, key):
        pass

    @abstractmethod
    def items(self):
        pass

    def pop(self, key, default=None):
        try:
            data = self[key]
        except KeyError:
            return default
        del self[key]
        return data

    @classmethod
    def from_uri(cls, db_uri, collection, db_name=None, ttl=None, **kwargs):
        url = urlparse(db_uri)

        if url.scheme == "mongodb":
            return MongoWrapper(
                db_uri=db_uri,
                db_name=db_name,
                collection=collection,
                ttl=ttl,
                extra_options=kwargs,
            )
        elif url.scheme == "redis" or url.scheme == "unix":
            return RedisWrapper(
                db_uri=db_uri,
                db_name=db_name,
                collection=collection,
                ttl=ttl,
                extra_options=kwargs,
            )
        elif url.scheme == "stateless":
            alg = parse_qs(url.query).get("alg") if url.query else None
            alg = alg[0] if alg else None
            return StatelessWrapper(
                collection=collection,
                encryption_key=url.password,
                alg=alg
            )

        return ValueError(f"Invalid DB URI: {db_uri}")

    @classmethod
    def type(cls, db_uri):
        url = urlparse(db_uri)
        if url.scheme == "mongodb":
            return "mongodb"
        elif url.scheme == "redis" or url.scheme == "unix":
            return "redis"
        elif url.scheme == "stateless":
            return "stateless"

        return ValueError(f"Invalid DB URI: {db_uri}")

    @property
    def ttl(self):
        return self._ttl


class MongoWrapper(StorageBase):
    def __init__(self, db_uri, db_name, collection, ttl=None, extra_options=None):
        if not _has_pymongo:
            raise ImportError("pymongo module is required but it is not available")

        if not extra_options:
            extra_options = {}

        mongo_options = extra_options.pop("mongo_kwargs", None) or {}

        self._db_uri = db_uri
        self._coll_name = collection
        self._db = MongoDB(db_uri, db_name=db_name, **mongo_options)
        self._coll = self._db.get_collection(collection)
        self._coll.create_index('lookup_key', unique=True)

        if ttl is None or (isinstance(ttl, int) and ttl >= 0):
            self._ttl = ttl
        else:
            raise ValueError("TTL must be a non-negative integer or None")
        if ttl is not None:
            self._coll.create_index(
                'last_modified',
                expireAfterSeconds=ttl,
                name="expiry"
            )

    def __setitem__(self, key, value):
        doc = {
            'lookup_key': key,
            'data': value,
            'last_modified': datetime.utcnow()
        }
        self._coll.replace_one({'lookup_key': key}, doc, upsert=True)

    def pack(self, value):
        raise NotImplementedError

    def __getitem__(self, key):
        doc = self._coll.find_one({'lookup_key': key})
        if not doc:
            raise KeyError(key)
        return doc['data']

    def __delitem__(self, key):
        self._coll.delete_one({'lookup_key': key})

    def __contains__(self, key):
        count = self._coll.count_documents({'lookup_key': key})
        return bool(count)

    def items(self):
        for doc in self._coll.find():
            yield (doc['lookup_key'], doc['data'])


class RedisWrapper(StorageBase):
    """
    Simple wrapper for a dict-like storage in Redis.
    Supports JSON-serializable data types.
    """

    def __init__(
        self, db_uri, *, db_name=None, collection, ttl=None, extra_options=None
    ):
        if not _has_redis:
            raise ImportError("redis module is required but it is not available")

        if not extra_options:
            extra_options = {}

        redis_kwargs = extra_options.pop("redis_kwargs", None) or {}
        redis_options = {
            "decode_responses": True, "db": db_name, **redis_kwargs
        }

        self._db = Redis.from_url(db_uri, **redis_options)
        self._collection = collection
        if ttl is None or (isinstance(ttl, int) and ttl >= 0):
            self._ttl = ttl
        else:
            raise ValueError("TTL must be a non-negative integer or None")

    def _make_key(self, key):
        if not isinstance(key, str):
            raise TypeError(f"Keys must be strings, {type(key).__name__} given")

        return ":".join([self._collection, key])

    def __setitem__(self, key, value):
        # Replacing the value of a key resets the ttl counter
        encoded = json.dumps({ "value": value })
        self._db.set(self._make_key(key), encoded, ex=self.ttl)

    def pack(self, value):
        raise NotImplementedError

    def __getitem__(self, key):
        encoded = self._db.get(self._make_key(key))
        if encoded is None:
            raise KeyError(key)
        return json.loads(encoded).get("value")

    def __delitem__(self, key):
        # Deleting a non-existent key is allowed
        self._db.delete(self._make_key(key))

    def __contains__(self, key):
        return (self._db.get(self._make_key(key)) is not None)

    def items(self):
        for key in self._db.keys(self._collection + "*"):
            visible_key = key[len(self._collection) + 1 :]

            if isinstance(visible_key, bytes):
                visible_key = visible_key.decode()

            try:
                yield (visible_key, self[visible_key])
            except KeyError:
                pass


class StatelessWrapper(StorageBase):
    def __init__(self, collection, encryption_key, alg=None):
        self.collection = collection
        if not alg or alg.lower() == "aes256":
            self.cipher = _AESCipher(encryption_key)
        else:
            raise ValueError(f"Invalid encryption algorithm: {alg}")

    def __setitem__(self, key, value):
        pass

    def pack(self, value):
        key = None
        if value:
            if isinstance(value, dict):
                value = json.dumps(value)
            key = self.cipher.encrypt(value.encode("UTF-8")).decode("UTF-8")
        return key

    def __getitem__(self, key):
        return self._unpack(key)

    def __delitem__(self, key):
        raise NotImplementedError

    def __contains__(self, key):
        if self._unpack(key):
            return True
        return False

    def items(self):
        raise NotImplementedError

    def _unpack(self, value):
        unpacked_val = None
        try:
            if value:
                unpacked_val = self.cipher.decrypt(value.encode("UTF-8")).decode("UTF-8")
                unpacked_val = json.loads(unpacked_val)
        except ValueError:
            if unpacked_val:
                logger.debug("Value '%s' is not a dict", value)
            else:
                logger.warning("Value '%s' is invalid for %s", value, self.collection)
        return unpacked_val


class MongoDB(object):
    """Simple wrapper to get pymongo real objects from the settings uri"""

    def __init__(self, db_uri, db_name=None, connection_factory=None, **kwargs):
        if db_uri is None:
            raise ValueError('db_uri not supplied')

        self._sanitized_uri = None
        self._parsed_uri = pymongo.uri_parser.parse_uri(db_uri)

        db_name = self._parsed_uri.get('database') or db_name
        if db_name is None:
            raise ValueError(
                "Database name must be provided either in the URI or as an argument"
            )
        self._database_name = self._parsed_uri['database'] = db_name

        if 'replicaSet' in kwargs and kwargs['replicaSet'] is None:
            del kwargs['replicaSet']

        self._options = self._parsed_uri.get('options')
        if connection_factory is None:
            connection_factory = pymongo.MongoClient
        if 'replicaSet' in kwargs:
            connection_factory = pymongo.MongoReplicaSetClient
        if 'replicaSet' in self._options and self._options['replicaSet'] is not None:
            connection_factory = pymongo.MongoReplicaSetClient
            kwargs['replicaSet'] = self._options['replicaSet']

        if 'replicaSet' in kwargs:
            if 'socketTimeoutMS' not in kwargs:
                kwargs['socketTimeoutMS'] = 5000
            if 'connectTimeoutMS' not in kwargs:
                kwargs['connectTimeoutMS'] = 5000

        self._db_uri = _format_mongodb_uri(self._parsed_uri)

        try:
            self._connection = connection_factory(
                host=self._db_uri,
                tz_aware=True,
                **kwargs)
        except pymongo.errors.ConnectionFailure as e:
            raise e

    def __repr__(self):
        return '<{!s}: {!s} {!s}>'.format(self.__class__.__name__,
                                          self._db_uri,
                                          self._database_name)

    @property
    def sanitized_uri(self):
        """
        Return the database URI we're using in a format sensible for logging etc.

        :return: db_uri
        """
        if self._sanitized_uri is None:
            _parsed = copy.copy(self._parsed_uri)
            if 'username' in _parsed:
                _parsed['password'] = 'secret'
            _parsed['nodelist'] = [_parsed['nodelist'][0]]
            self._sanitized_uri = _format_mongodb_uri(_parsed)
        return self._sanitized_uri

    def get_connection(self):
        """
        Get the raw pymongo connection object.
        :return: Pymongo connection object
        """
        return self._connection

    def get_database(self, database_name=None, username=None, password=None):
        """
        Get a pymongo database handle, after authenticating.

        Authenticates using the username/password in the DB URI given to
        __init__() unless username/password is supplied as arguments.

        :param database_name: (optional) Name of database
        :param username: (optional) Username to login with
        :param password: (optional) Password to login with
        :return: Pymongo database object
        """
        if database_name is None:
            database_name = self._database_name
        if database_name is None:
            raise ValueError('No database_name supplied, and no default provided to __init__')
        db = self._connection[database_name]
        if username and password:
            db.authenticate(username, password)
        elif self._parsed_uri.get("username", None):
            if 'authSource' in self._options and self._options['authSource'] is not None:
                db.authenticate(
                    self._parsed_uri.get("username", None),
                    self._parsed_uri.get("password", None),
                    source=self._options['authSource']
                )
            else:
                db.authenticate(
                    self._parsed_uri.get("username", None),
                    self._parsed_uri.get("password", None)
                )
        return db

    def get_collection(self, collection, database_name=None, username=None, password=None):
        """
        Get a pymongo collection handle.

        :param collection: Name of collection
        :param database_name: (optional) Name of database
        :param username: (optional) Username to login with
        :param password: (optional) Password to login with
        :return: Pymongo collection object
        """
        _db = self.get_database(database_name, username, password)
        return _db[collection]

    def close(self):
        self._connection.close()


def _format_mongodb_uri(parsed_uri):
    """
    Painstakingly reconstruct a MongoDB URI parsed using pymongo.uri_parser.parse_uri.

    :param parsed_uri: Result of pymongo.uri_parser.parse_uri
    :type parsed_uri: dict

    :return: New URI
    :rtype: str | unicode
    """
    user_pass = ''
    if parsed_uri.get('username') and parsed_uri.get('password'):
        user_pass = '{username!s}:{password!s}@'.format(**parsed_uri)

    _nodes = []
    for host, port in parsed_uri.get('nodelist'):
        if ':' in host and not host.endswith(']'):
            # IPv6 address without brackets
            host = '[{!s}]'.format(host)
        if port == 27017:
            _nodes.append(host)
        else:
            _nodes.append('{!s}:{!s}'.format(host, port))
    nodelist = ','.join(_nodes)

    options = ''
    if parsed_uri.get('options'):
        _opt_list = []
        for key, value in parsed_uri.get('options').items():
            if isinstance(value, bool):
                value = str(value).lower()
            _opt_list.append('{!s}={!s}'.format(key, value))
        options = '?' + '&'.join(_opt_list)

    db_name = parsed_uri.get('database') or ''

    res = "mongodb://{user_pass!s}{nodelist!s}/{db_name!s}{options!s}".format(
        user_pass=user_pass,
        nodelist=nodelist,
        db_name=db_name,
        # collection is ignored
        options=options)
    return res
