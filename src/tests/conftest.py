# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Galter Health Sciences Library & Learning Center.
#
# Invenio-LDAPClient is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pytest configuration."""

from __future__ import absolute_import, print_function

import shutil
import tempfile
import importlib.resources

import pytest
from flask import Flask
from flask_babel import Babel
from invenio_i18n import InvenioI18N

from ldap3 import Server, ServerPool, Connection, MOCK_SYNC, ROUND_ROBIN
import ssl
test_resource_path = str(importlib.resources.files('tests')/'resources')

@pytest.fixture()
def instance_path():
    """Temporary instance path."""
    path = tempfile.mkdtemp()
    yield path
    shutil.rmtree(path)


@pytest.fixture()
def app(instance_path):
    app_ = Flask('testapp', instance_path=instance_path)

    app_.config.update(
        SECRET_KEY='SECRET_KEY',
        TESTING=True,
    )

    Babel(app_)
    InvenioI18N(app_)

    with app_.app_context():
        yield app_


group_filters = [lambda u : f'(&(memberUid={u})(objectClass=posixGroup)(cn=green))',
                 lambda u : f'(&(memberUid={u})(objectClass=posixGroup)(cn=blue))']


user_filter = lambda u : f'(&(uid={u})(objectClass=posixAccount))'

        
@pytest.fixture()
def configured_app(app):
    bind_base = lambda u : f'uid={u},ou=People,ou=Local,o=Example,dc=example,dc=com'
    
    app.config.update(WTF_CSRF_ENABLED = False,
                      COVER_TEMPLATE = 'some/template.html',
                      LDAPCLIENT_EXCLUSIVE_AUTHENTICATION = True,
                      LDAPCLIENT_SERVER_KWARGS = {
                          'host': 'ldap.0.example.com',
                          'port': 389,
                          'use_ssl': False,
                          'tls': None},
                      LDAPCLIENT_FULL_NAME_ATTRIBUTE = 'displayName',
                      LDAPCLIENT_BIND_BASE = bind_base,
                      LDAPCLIENT_USER_SEARCH_BASE = 'ou=People,ou=Local,o=Example,dc=example,dc=com',
                      LDAPCLIENT_USER_SEARCH_FILTER = user_filter,
                      LDAPCLIENT_CONNECTION_KWARGS = {'client_strategy': MOCK_SYNC},
                      LDAPCLIENT_GROUP_SEARCH_BASE = 'ou=Groups,ou=Local,o=Example,dc=example,dc=com',
                      LDAPCLIENT_GROUP_FILTERS = group_filters
                      )
    return app

@pytest.fixture()
def strangely_configured_app(app):
    '''
    This is just to hit the if not connection.entries branch in .forms
    '''
    bind_base = lambda u : f'uid={u},ou=People,o=Example,dc=example,dc=com'
    
    app.config.update(WTF_CSRF_ENABLED = False,
                      LDAPCLIENT_EXCLUSIVE_AUTHENTICATION = True,
                      LDAPCLIENT_SERVER_KWARGS = {
                          'host': 'ldap.0.example.com',
                          'port': 389,
                          'use_ssl': False,
                          'tls': None},
                      LDAPCLIENT_FULL_NAME_ATTRIBUTE = 'displayName',
                      LDAPCLIENT_BIND_BASE = bind_base,
                      LDAPCLIENT_USER_SEARCH_BASE = 'ou=Local,o=Example,dc=example,dc=com',
                      LDAPCLIENT_USER_SEARCH_FILTER = user_filter,
                      LDAPCLIENT_CONNECTION_KWARGS = {'client_strategy': MOCK_SYNC},
                      LDAPCLIENT_GROUP_SEARCH_BASE = 'ou=Groups,ou=Local,o=Example,dc=example,dc=com',
                      LDAPCLIENT_GROUP_FILTERS = group_filters
                      )
    return app

@pytest.fixture()
def configured_app_with_server_pool(app):
    bind_base = lambda u : f'uid={u},ou=People,ou=Local,o=Example,dc=example,dc=com'
    
    app.config.update(WTF_CSRF_ENABLED = False,
                      LDAPCLIENT_EXCLUSIVE_AUTHENTICATION = True,
                      LDAPCLIENT_SERVER_KWARGS = [
                          {'host': 'ldap.0.example.com',
                           'port': 389,
                           'use_ssl': False,
                           'tls': None},
                          {'host': 'ldap.1.example.com',
                           'port': 389,
                           'use_ssl': False,
                           'tls': None},],
                      LDAPCLIENT_SERVER_POOL_KWARGS = {'active': True, 'exhaust': False, 'pool_strategy': ROUND_ROBIN}, 
                      LDAPCLIENT_FULL_NAME_ATTRIBUTE = 'displayName',
                      LDAPCLIENT_BIND_BASE = bind_base,
                      LDAPCLIENT_USER_SEARCH_BASE = 'ou=People,ou=Local,o=Example,dc=example,dc=com',
                      LDAPCLIENT_USER_SEARCH_FILTER = user_filter,
                      LDAPCLIENT_CONNECTION_KWARGS = {'client_strategy': MOCK_SYNC},
                      LDAPCLIENT_GROUP_SEARCH_BASE = 'ou=Groups,ou=Local,o=Example,dc=example,dc=com',
                      LDAPCLIENT_GROUP_FILTERS = group_filters
                )
    return app



@pytest.fixture()
def mock_server_factory():
    def _factory(name):
        server = Server.from_definition(name,
                                        test_resource_path + '/mock_ldap_server.json',
                                        test_resource_path + '/mock_ldap_server_schema.json')

        conn = Connection(server,
                          user = 'uid=admin,dc=example,dc=com',
                          password = 'secret321',
                          client_strategy = MOCK_SYNC)

        conn.strategy.add_entry('uid=admin,dc=example,dc=com',
                                {'userPassword': 'secret321'})

        with conn:
            dn = 'o=Example,dc=example,dc=com'
            conn.add(dn=dn,
                     object_class='organization',
                     attributes={'o': 'Example'})

            dn = 'ou=People,o=Example,dc=example,dc=com'
            conn.add(dn=dn,
                     object_class='organizationalUnit')

            dn = 'ou=Local,o=Example,dc=example,dc=com'
            conn.add(dn=dn,
                     object_class='organizationalUnit')

            dn = 'ou=People,ou=Local,o=Example,dc=example,dc=com'
            conn.add(dn=dn,
                     object_class='organizationalUnit')

            dn = 'ou=Groups,ou=Local,o=Example,dc=example,dc=com'
            conn.add(dn=dn,
                     object_class='organizationalUnit')

            #Sited in different part of DIT
            uidNumber = 0
            dn = f'uid=testuser{uidNumber},ou=People,o=Example,dc=example,dc=com'
            conn.add(dn=dn,
                     object_class=['inetOrgPerson','posixAccount','shadowAccount'],
                     attributes={'homeDirectory': f'/home/testuser{uidNumber}',
                                 'sn': 'Testuser',
                                 'cn': f'Test User {uidNumber}',
                                 'displayName': f'Test User {uidNumber}',
                                 'uidNumber': uidNumber,
                                 'gidNumber': 0,
                                 'mail': f'testuser{uidNumber}@example.com',
                                 'userPassword': 'secret123'
                                 })

            #Has everything: mail, displayName and group membership
            uidNumber = 1
            dn = f'uid=testuser{uidNumber},ou=People,ou=Local,o=Example,dc=example,dc=com'
            conn.add(dn=dn,
                     object_class=['inetOrgPerson','posixAccount','shadowAccount'],
                     attributes={'homeDirectory': f'/home/testuser{uidNumber}',
                                 'sn': 'Testuser',
                                 'cn': f'Test User {uidNumber}',
                                 'displayName': f'Test User {uidNumber}',
                                 'uidNumber': uidNumber,
                                 'gidNumber': 0,
                                 'mail': f'testuser{uidNumber}@example.com',
                                 'userPassword': 'secret123'
                                 })

            #Does not belong to required groups (green or blue)
            uidNumber = 2
            dn = f'uid=testuser{uidNumber},ou=People,ou=Local,o=Example,dc=example,dc=com'
            conn.add(dn=dn,
                     object_class=['inetOrgPerson','posixAccount','shadowAccount'],
                     attributes={'homeDirectory': f'/home/testuser{uidNumber}',
                                 'sn': 'Testuser',
                                 'cn': f'Test User {uidNumber}',
                                 'displayName': f'Test User {uidNumber}',
                                 'uidNumber': uidNumber,
                                 'gidNumber': 0,
                                 'mail': f'testuser{uidNumber}@example.com',
                                 'userPassword': 'secret123'
                                 })

            #No email attribute
            uidNumber = 3
            dn = f'uid=testuser{uidNumber},ou=People,ou=Local,o=Example,dc=example,dc=com'
            conn.add(dn=dn,
                     object_class=['inetOrgPerson','posixAccount','shadowAccount'],
                     attributes={'homeDirectory': f'/home/testuser{uidNumber}',
                                 'sn': 'Testuser',
                                 'cn': f'Test User {uidNumber}',
                                 'displayName': f'Test User {uidNumber}',
                                 'uidNumber': uidNumber,
                                 'gidNumber': 0,
                                 'userPassword': 'secret123'
                                 })

            #No displayName
            uidNumber = 4
            dn = f'uid=testuser{uidNumber},ou=People,ou=Local,o=Example,dc=example,dc=com'
            conn.add(dn=dn,
                     object_class=['inetOrgPerson','posixAccount','shadowAccount'],
                     attributes={'homeDirectory': f'/home/testuser{uidNumber}',
                                 'sn': 'Testuser',
                                 'cn': f'Test User {uidNumber}',
                                 'uidNumber': uidNumber,
                                 'gidNumber': 0,
                                 'mail': f'testuser{uidNumber}@example.com',
                                 'userPassword': 'secret123'
                                 })

            #Red group: all users
            dn = 'cn=red,ou=Groups,ou=Local,o=Example,dc=example,dc=com'
            conn.add(dn=dn,
                     object_class='posixGroup',
                     attributes={'gidNumber': 0,
                                 'memberUid': ['testuser0',
                                               'testuser1',
                                               'testuser2',
                                               'testuser3',
                                               'testuser4']})

            #Green group
            dn = 'cn=green,ou=Groups,ou=Local,o=Example,dc=example,dc=com'
            conn.add(dn=dn,
                     object_class='posixGroup',
                     attributes={'gidNumber': 1,
                                 'memberUid': ['testuser0',
                                               'testuser1',                                    
                                               'testuser3',
                                               'testuser4']})

            #Blue group
            dn = 'cn=blue,ou=Groups,ou=Local,o=Example,dc=example,dc=com'
            conn.add(dn=dn,
                     object_class='posixGroup',
                     attributes={'gidNumber': 1,
                                 'memberUid': ['testuser1',                                    
                                               'testuser3',
                                               'testuser4']})

            return server
        
    return _factory


