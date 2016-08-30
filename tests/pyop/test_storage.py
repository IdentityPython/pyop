# -*- coding: utf-8 -*-

import pytest

from pyop.storage import MongoWrapper

__author__ = 'lundberg'


@pytest.mark.usefixtures('mongodb')
class TestMongoStorage(object):
    @pytest.fixture()
    def db(self, mongodb):
        return MongoWrapper(mongodb.get_uri(), 'pyop', 'test')

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
