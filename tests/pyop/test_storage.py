# -*- coding: utf-8 -*-

import pytest

from abc import ABC, abstractmethod
from contextlib import contextmanager
from redis.client import Redis
import datetime
import fakeredis
import mongomock
import pymongo
import time

import pyop.storage

__author__ = 'lundberg'


db_specs_list = [
    {"uri": "mongodb://localhost:1234/pyop", "name": "pyop"},
    {"uri": "redis://localhost/0", "name": 0},
]


@pytest.fixture(autouse=True)
def mock_redis(monkeypatch):
    def mockreturn(*args, **kwargs):
        return fakeredis.FakeStrictRedis(*args, **kwargs)
    monkeypatch.setattr(Redis, "from_url", mockreturn)

@pytest.fixture(autouse=True)
def mock_mongo():
    pymongo.MongoClient = mongomock.MongoClient


class TestStorage(object):
    @pytest.fixture(params=db_specs_list)
    def db(self, request):
        return pyop.storage.StorageBase.from_uri(
            request.param["uri"], db_name=request.param["name"], collection="test"
        )

    def test_write(self, db):
        db['foo'] = 'bar'
        assert db['foo'] == 'bar'

    def test_multilevel_dict(self, db):
        db['foo'] = {}
        assert db['foo'] == {}
        db['foo'] = {'bar': 'baz'}
        assert db['foo']['bar'] == 'baz'

    def test_contains(self, db):
        db['foo'] = 'bar'
        assert 'foo' in db

    def test_pop(self, db):
        db['foo'] = 'bar'
        assert db.pop('foo') == 'bar'
        try:
            db['foo']
        except Exception as e:
            assert isinstance(e, KeyError)

    def test_items(self, db):
        db['foo'] = 'foorbar'
        db['bar'] = True
        db['baz'] = {'foo': 'bar'}
        for key, item in db.items():
            assert key
            assert item

    @pytest.mark.parametrize(
        "args,kwargs",
        [
            (["mongodb://localhost/pyop"], {"collection": "test", "ttl": 3}),
            (["mongodb://localhost"], {"db_name": "pyop", "collection": "test"}),
            (["mongodb://localhost", "test", "pyop"], {}),
            (["mongodb://localhost/pyop", "test"], {}),
            (["mongodb://localhost/pyop"], {"db_name": "other", "collection": "test"}),
            (["redis://localhost"], {"collection": "test"}),
            (["redis://localhost", "test"], {}),
            (["redis://localhost"], {"db_name": 2, "collection": "test"}),
            (["unix://localhost/0"], {"collection": "test", "ttl": 3}),
        ],
    )
    def test_from_uri(self, args, kwargs):
        store = pyop.storage.StorageBase.from_uri(*args, **kwargs)
        store["test"] = "value"
        assert store["test"] == "value"

    @pytest.mark.parametrize(
        "error,args,kwargs",
        [
            (ValueError, ["mongodb://localhost"], {"collection": "test", "ttl": None}),
            (
                TypeError,
                ["mongodb://localhost", "ouch"],
                {"db_name": 3, "collection": "test", "ttl": None},
            ),
            (
                TypeError,
                ["mongodb://localhost", "ouch"],
                {"db_name": "pyop", "collection": "test", "ttl": None},
            ),
            (
                TypeError,
                ["mongodb://localhost", "pyop"],
                {"collection": "test", "ttl": None},
            ),
            (
                TypeError,
                ["redis://localhost", "ouch"],
                {"db_name": 3, "collection": "test", "ttl": None},
            ),
            (TypeError, ["redis://localhost/0"], {}),
            (TypeError, ["redis://localhost/0"], {"db_name": "pyop"}),
        ],
    )
    def test_from_uri_invalid_parameters(self, error, args, kwargs):
        with pytest.raises(error):
            pyop.storage.StorageBase.from_uri(*args, **kwargs)


class StorageTTLTest(ABC):
    def prepare_db(self, uri, ttl):
        self.db = pyop.storage.StorageBase.from_uri(
            uri,
            collection="test",
            ttl=ttl,
        )
        self.db["foo"] = {"bar": "baz"}

    @abstractmethod
    def set_time(self, offset, monkey):
        pass

    @contextmanager
    def adjust_time(self, offset):
        mp = pytest.MonkeyPatch()
        try:
            yield self.set_time(offset, mp)
        finally:
            mp.undo()

    def execute_ttl_test(self, uri, ttl):
        self.prepare_db(uri, ttl)
        assert self.db["foo"]
        with self.adjust_time(offset=int(ttl / 2)):
            assert self.db["foo"]
        with self.adjust_time(offset=int(ttl * 2)):
            with pytest.raises(KeyError):
                self.db["foo"]

    @pytest.mark.parametrize("spec", db_specs_list)
    @pytest.mark.parametrize("ttl", ["invalid", -1, 2.3, {}])
    def test_invalid_ttl(self, spec, ttl):
        with pytest.raises(ValueError):
            self.prepare_db(spec["uri"], ttl)


class TestRedisTTL(StorageTTLTest):
    def set_time(self, offset, monkeypatch):
        now = time.time()
        def new_time():
            return now + offset

        monkeypatch.setattr(time, "time", new_time)

    def test_ttl(self):
        self.execute_ttl_test("redis://localhost/0", 3600)

    def test_missing_module(self):
        pyop.storage._has_redis = False
        self.prepare_db("mongodb://localhost/0", None)
        with pytest.raises(ImportError):
            self.prepare_db("redis://localhost/0", None)
        pyop.storage._has_redis = True


class TestMongoTTL(StorageTTLTest):
    def set_time(self, offset, monkeypatch):
        now = datetime.datetime.utcnow()
        def new_time():
            return now + datetime.timedelta(seconds=offset)

        monkeypatch.setattr(mongomock, "utcnow", new_time)

    def test_ttl(self):
        self.execute_ttl_test("mongodb://localhost/pyop", 3600)

    def test_missing_module(self):
        pyop.storage._has_pymongo = False
        self.prepare_db("redis://localhost/0", None)
        with pytest.raises(ImportError):
            self.prepare_db("mongodb://localhost/0", None)
        pyop.storage._has_pymongo = True


class TestStatelessWrapper(object):
    @pytest.fixture
    def db(self):
        return pyop.storage.StatelessWrapper("pyop", "abc123")

    def test_write(self, db):
        db['foo'] = 'bar'
        assert db['foo'] is None

    def test_pack_and_unpack(self, db):
        val_1 = {'foo': 'bar'}
        key = db.pack(val_1)
        val_2 = db[key]
        assert val_1 == val_2

    def test_pack_with_non_dict_val(self, db):
        val_1 = 'this is not a dict'
        key = db.pack(val_1)
        val_2 = db[key]
        assert val_1 == val_2

    def test_contains(self, db):
        val_1 = {'foo': 'bar'}
        key = db.pack(val_1)
        assert key in db

    def test_items(self, db):
        with pytest.raises(NotImplementedError):
            db['foo'] = 'bar'
            db.items()

    def test_delitem(self, db):
        with pytest.raises(NotImplementedError):
            db['foo'] = 'bar'
            del db['foo']