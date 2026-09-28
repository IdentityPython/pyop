import pytest

from pyop.provider import Provider


class MockAuthzState:
    def __init__(self):
        self.stateless = False


class MockUserinfo:
    pass


class ClientRepo: # A basic ClientRepo with fixed initial clients
    clients: dict 

    def get_all(self):
        return self.clients

            
class TestProviderClients:
    def setup_method(self):
        self.config = {
            'issuer': 'https://test',
            'authorization_endpoint': 'https://test/auth',
            'token_endpoint': 'https://test/token',
            'userinfo_endpoint': 'https://test/userinfo',
            'jwks_uri': 'https://test/jwks'
        }
        self.mock_authz = MockAuthzState()
        self.mock_userinfo = MockUserinfo()

    def test_clients_dict_direct_modification_and_set(self):
        clients_dict = {'client1': {'name': 'test'}}
        provider = Provider(None, self.config, self.mock_authz, clients_dict, self.mock_userinfo)
        
        provider.clients['client3'] = {'name': 'added'}
        assert 'client3' in provider.clients
        assert provider.clients['client3'] == {'name': 'added'}
        
        new_clients = {'client4': {'name': 'new'}, 'client5': {'name': 'new2'}}
        provider.clients = new_clients
        assert provider.clients == new_clients
        
    def test_clients_callable_indirect_modification(self):
        repo = ClientRepo()
        expected_initial = {'client2': {'name': 'callable_test'}}
        repo.clients = expected_initial
        
        provider = Provider(None, self.config, self.mock_authz, repo.get_all, self.mock_userinfo)
        assert provider.clients == expected_initial
        
        repo.clients['client3'] = {'name': 'added'}
        assert 'client2' in provider.clients
        assert provider.clients['client3'] == {'name': 'added'}
        assert len(provider.clients) == 2
        
        del repo.clients['client3']
        assert 'client2' in provider.clients
        assert 'client3' not in provider.clients
        assert len(provider.clients) == 1

