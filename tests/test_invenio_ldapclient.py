# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Galter Health Sciences Library & Learning Center.
#
# Invenio-LDAPClient is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Module tests."""

from __future__ import absolute_import, print_function

from unittest.mock import MagicMock, Mock, patch, create_autospec

import invenio_accounts
import ldap3
import pytest
import ssl
from flask import Flask
from invenio_accounts import InvenioAccountsUI
from invenio_accounts.models import User
from invenio_userprofiles.models import UserProfile
from werkzeug.local import LocalProxy

import invenio_ldapclient
from invenio_ldapclient import InvenioLDAPClient

def test_version():
    """Test version import."""
    from invenio_ldapclient import __version__
    assert __version__

def test_init():
    """Test extension initialization."""
    app = Flask('testapp')
    _SERVER_INFO = [{'hostname': 'example_one.com',
                               'port': 389,
                               'use_ssl': False},
                              {'hostname': 'example_two.com',
                               'port': 5000,
                               'use_ssl': False},]

    _SEARCH_INFO = {'search_base': 'dc=example,dc=com',
                    'bind_base': 'ou=people,dc=example,dc=com',
                    'username_attribute': 'uid',
                    'email_attribute': 'mail',
                    'fullname_attribute': 'displayName',
                    'search_attributes': None}

    
                              
    app.config.update(LDAPCLIENT_SERVERS = _SERVER_INFO)
    app.config.update(LDAPCLIENT_SEARCH = _SEARCH_INFO)

                      
    ext = InvenioLDAPClient(app)
    assert 'invenio-ldapclient' in app.extensions
    
    assert app.config['LDAPCLIENT_AUTHENTICATION'] is True
    assert app.config['LDAPCLIENT_FIND_BY_EMAIL'] is True
    assert app.config['LDAPCLIENT_AUTO_REGISTRATION'] is True
    assert app.config['LDAPCLIENT_EXCLUSIVE_AUTHENTICATION'] is True
    assert app.config['LDAPCLIENT_LOGIN_USER_TEMPLATE'] == \
        'invenio_ldapclient/login_user.html'


    assert app.config['LDAPCLIENT_SERVERS'][0]['hostname'] == 'example_one.com'
    assert app.config['LDAPCLIENT_SERVERS'][0]['port'] == 389
    assert app.config['LDAPCLIENT_SERVERS'][0]['use_ssl'] == False

    assert app.config['LDAPCLIENT_SERVERS'][1]['hostname'] == 'example_two.com'
    assert app.config['LDAPCLIENT_SERVERS'][1]['port'] == 5000
    assert app.config['LDAPCLIENT_SERVERS'][1]['use_ssl'] == False

    
    assert app.config['LDAPCLIENT_CUSTOM_CONNECTION'] is None
    assert app.config['LDAPCLIENT_SEARCH']['search_base'] == 'dc=example,dc=com'
    assert app.config['LDAPCLIENT_SEARCH']['bind_base'] == 'ou=people,dc=example,dc=com'
    assert app.config['LDAPCLIENT_SEARCH']['username_attribute'] == 'uid'
    assert app.config['LDAPCLIENT_SEARCH']['email_attribute'] == 'mail'
    assert app.config['LDAPCLIENT_SEARCH']['fullname_attribute'] == 'displayName'
    assert app.config['LDAPCLIENT_SEARCH']['search_attributes'] is None
    assert app.config['SECURITY_LOGIN_USER_TEMPLATE'] == \
        app.config['LDAPCLIENT_LOGIN_USER_TEMPLATE']    

    
def test_init_non_exclusive_LDAP_auth():
    '''
    SECURITY_LOGIN_USER_TEMPLATE is in invenio_accounts.config
    
    This implies InvenioLDAPClient should be initialised before InvenioAccountsREST
    and InvenioAccountsUI

    LDAPCLIENT_EXCLUSIVE_AUTHENTICATION is set False, InvenioAccounts* will set
    SECURITY_LOGIN_USER_TEMPLATE
    '''
    app = Flask('testapp')
    app.config['LDAPCLIENT_EXCLUSIVE_AUTHENTICATION'] = False
    ext = InvenioLDAPClient(app)
    #<----- LB - init_app(app) is called inside class cnstr
    # calling 2nd time attempts to re-register .views.blueprint
    # which prompts flask.blueprints to raise ValueError.
    #
    #ext.init_app(app)
    #----->
    assert app.config['LDAPCLIENT_EXCLUSIVE_AUTHENTICATION'] is False
    #<----- LB - pytest.raises: message -> match (v8.2.2)
    #with pytest.raises(KeyError, message='SECURITY_LOGIN_USER_TEMPLATE'):
    #----->
    with pytest.raises(KeyError, match='SECURITY_LOGIN_USER_TEMPLATE'):
        assert app.config['SECURITY_LOGIN_USER_TEMPLATE']


# View tests
def test_get_ldap_login(app):
    '''
    We get a 200 OK

    with LDAPCLIENT_EXCLUSIVE_AUTHENTICATION True we get the appropriate template
    '''
    app.config['LDAPCLIENT_EXCLUSIVE_AUTHENTICATION'] = True
    app.config['LDAPCLIENT_USERNAME_PLACEHOLDER'] = 'Da User'
    app.config['COVER_TEMPLATE'] = 'login.html'
    app.jinja_loader.searchpath.append('tests/templates')
    app.jinja_loader.searchpath.append(
        invenio_accounts.__path__[0] + '/templates'
    )
    app.extensions['security'] = Mock()
    InvenioLDAPClient(app)

    response = app.test_client().get("/ldap-login")

    assert response.status_code == 200
    html_text = response.get_data(as_text=True)
    assert 'placeholder="Da User"' in html_text


def test_view_for_ldap_connection_returns_False_flashes_error(app):
    """Test view when there's something wrong with LDAP connection.
    
    SECURITY_POST_LOGIN_VIEW used to redirect if url_has_allowed_host_and_scheme returns False
    """
    app.extensions['security'] = Mock()
    app.config['COVER_TEMPLATE'] = 'login.html'
    app.config['SECURITY_POST_LOGIN_VIEW'] = '/abc'
    app.config['WTF_CSRF_ENABLED'] = False
    InvenioLDAPClient(app)
    app.jinja_loader.searchpath.append('tests/templates')
    app.jinja_loader.searchpath.append(
        invenio_accounts.__path__[0] + '/templates'
    )

    with patch('invenio_ldapclient.views._ldap_connection',
               autospec=True, return_value=False) as ldap_conn_mock:
        response = app.test_client().post(
            "/ldap-login",
            data=dict(username='bad', password='bad')
        )
        html_text = response.get_data(as_text=True)

    ldap_conn_mock.assert_called_once()
    assert app.config['SECURITY_CONFIRMABLE'] is False
    assert app.config['SECURITY_RECOVERABLE'] is False
    assert app.config['SECURITY_REGISTERABLE'] is False
    assert app.config['SECURITY_CHANGEABLE'] is False
    assert app.config['USERPROFILES_EMAIL_ENABLED'] is False
    assert app.view_functions['security.login'] == \
        invenio_ldapclient.views.ldap_login
    assert (
        "We couldn&#39;t log you in, please check your password." in html_text
    )


@patch('invenio_ldapclient.views.login_user', lambda user, remember: True)
@patch('invenio_ldapclient.views.db.session.commit', lambda: True)
def test_view_ldap_connection_returns_True(app):
    """Test view when LDAP connection is A-OK."""
    app.extensions['security'] = Mock()
    InvenioLDAPClient(app)
    app.config['SECURITY_POST_LOGIN_VIEW'] = '/abc'
    app.config['WTF_CSRF_ENABLED'] = False
    ldap_conn = Mock(bind=lambda: True, unbind=lambda: True)
    user = Mock()

    @patch('invenio_ldapclient.views.after_this_request', autospec=True)
    @patch('invenio_ldapclient.views._find_or_register_user', autospec=True,
           return_value=user)
    @patch('invenio_ldapclient.views._ldap_connection', autospec=True,
           return_value=ldap_conn)
    def patched_test(ldap_conn_mock, find_register_mock, after_request_mock):
        res = app.test_client().post(
            "/ldap-login",
            data=dict(username='itsame', password='good')
        )
        lform = ldap_conn_mock.call_args[0][0]
        assert lform.username.data == 'itsame'
        assert lform.password.data == 'good'
        assert ldap_conn_mock.called is True
        find_register_mock.assert_called_once_with(ldap_conn, 'itsame')
        after_request_mock.assert_called_once_with(
            invenio_ldapclient.views._commit
        )
        assert app.view_functions['security.login'] == \
            invenio_ldapclient.views.ldap_login
        assert res.status_code == 302
        #<----- LB - location field is /abc
        #
        #assert res.location == 'http://localhost/abc'
        #----->
        assert res.location == '/abc'
        

    patched_test()
        
def test_view__ldap_connection(app):
    InvenioLDAPClient(app)
        
    from invenio_ldapclient.views import _ldap_connection as subject

    # Form cannot be validated
    form_invalid = Mock(validate_on_submit=lambda: False)
    assert subject(form_invalid) is False
    
    # Form missing required info
    form_no_user = Mock(
        validate_on_submit=lambda: True,
        password=Mock(data='pass'),
        username=Mock(data='')
    )
    assert subject(form_no_user) is False
    
    # With default TLS and Connection    
    app.config['LDAPCLIENT_SERVERS'] = [{'host': 'ldap.host',
                                         'port': 666,
                                         'use_ssl': True}]                                           
    
    app.config['LDAPCLIENT_SEARCH']['bind_base'] = 'ou=base,cn=test'
    app.config['LDAPCLIENT_SEARCH']['group_filters'] = \
        [lambda user : '(&(memberUid={user})(cn=red)(objectClass=posixGroup))',
         lambda user : '(&(memberUid={user})(cn=blue)(objectClass=posixGroup))',]
         

    form_valid = Mock(
        validate_on_submit=lambda: True,
        password=Mock(data='dapass'),
        username=Mock(data='itsame')
    )

    @patch('invenio_ldapclient.views.Connection.bind', lambda self : True)
    @patch('invenio_ldapclient.views.Connection.search')
    def test_valid_connection_group_member(mocked_search):
        mocked_search.side_effect = [True, False]
        
        conn = subject(form_valid)
    
        assert type(conn) == ldap3.core.connection.Connection
        assert conn.user == 'uid=itsame,ou=base,cn=test'
        assert conn.password == 'dapass'
        assert type(conn.server) == ldap3.core.server.Server
        assert conn.server.port == 666
        assert conn.server.host == 'ldap.host'
        assert conn.server.ssl is True
        assert type(conn.server.tls) == ldap3.core.tls.Tls
        assert conn.server.tls.validate == 0

    @patch('invenio_ldapclient.views.Connection.bind', lambda self : True)
    @patch('invenio_ldapclient.views.Connection.search')
    def test_valid_connection_not_group_member(mocked_search):
        mocked_search.side_effect = [False, False]
        
        conn = subject(form_valid)

        assert conn is None
    
    @patch('invenio_ldapclient.views.Connection.bind', lambda self : True)
    @patch('invenio_ldapclient.views.Connection.search')
    def test_valid_connection_group_member_non_default_tls(mocked_search):
        mocked_search.side_effect = [True, False]
        
        app.config['LDAPCLIENT_SERVERS'][0]['tls'] = ldap3.core.tls.Tls()

        conn = subject(form_valid)
        assert conn.server.tls == app.config['LDAPCLIENT_SERVERS'][0]['tls']

    test_valid_connection_group_member()
    test_valid_connection_not_group_member()
    test_valid_connection_group_member_non_default_tls()



    '''
    # With non-default Connection
    app.config['LDAPCLIENT_CUSTOM_CONNECTION'] = \
    lambda u, p: 'User: {}, Pass: {}'.format(u, p)
    assert subject(form_valid) == 'User: itsame, Pass: dapass'
    '''

@patch('invenio_ldapclient.views._search_ldap', lambda x, y: None)
def test_view__find_or_register_user_no_email(app):
    InvenioLDAPClient(app)
    app.config['LDAPCLIENT_SEARCH']['email_attribute'] = 'daMail'
    subject = invenio_ldapclient.views._find_or_register_user
    conn = Mock(entries=[{'daMail': Mock(values=[])}])
    assert subject(conn, 'itsame') is None


@patch('invenio_ldapclient.views._search_ldap', lambda x, y: None)
def test_view__find_or_register_active_user_found_by_username(app):
    InvenioLDAPClient(app)
    
    subject = invenio_ldapclient.views._find_or_register_user
    conn = Mock(entries=[{'mail': Mock(values=['itsame@ta.da'])}])
    user = Mock(active=True)

    #def filter_by_username(username):
        #username = username_obj.get_children()[1].value
        #assert username == 'itsame'
    #    return Mock(one_or_none=lambda: user)

    #user_mock = Mock(
    #    query=Mock(
    #        join=lambda obj: Mock(
    #            filter=MagicMock(
    #                side_effect=filter_by_username))))

    user_mock = Mock(query = \
                     Mock(filter_by = lambda username : Mock(one_or_none = lambda : user)))
                
    @patch('invenio_ldapclient.views.User', user_mock)
    @patch(
        'invenio_ldapclient.views._register_or_update_user',
        return_value=user
    )
    def assert_returns_user(mocks):
        assert subject(conn, 'itsame') == user

    assert_returns_user()

@patch('invenio_ldapclient.views._search_ldap', lambda x, y: None)
def test_view__find_or_register_inactive_user_found_by_username(app):
    InvenioLDAPClient(app)
    subject = invenio_ldapclient.views._find_or_register_user
    conn = Mock(entries=[{'mail': Mock(values=['itsame@ta.da'])}])
    user = Mock(active=False)

    #def filter_by_username(username_obj):
    #    username = username_obj.get_children()[1].value
    #    assert username == 'itsame'
    #    return Mock(one_or_none=lambda: user)

    #user_mock = Mock(
    #    query=Mock(
    #        join=lambda obj: Mock(
    #            filter=MagicMock(
    #                side_effect=filter_by_username))))

    user_mock = Mock(query = \
                     Mock(filter_by = lambda username : Mock(one_or_none = lambda : user)))

    @patch('invenio_ldapclient.views.User', user_mock)
    @patch(
        'invenio_ldapclient.views._register_or_update_user',
        return_value=user
    )
    def assert_returns_none(mocks):
        assert subject(conn, 'itsame') is None

    assert_returns_none()


@patch('invenio_ldapclient.views._search_ldap', lambda x, y: None)
def test_view__find_or_register_active_user_found_by_email(app):
    InvenioLDAPClient(app)
    subject = invenio_ldapclient.views._find_or_register_user
    conn = Mock(entries=[{'mail': Mock(values=['itsame@ta.da'])}])
    user = Mock(active=True)

    def _filter_by(username=None, email=None):
        if email is None:
            return Mock(one_or_none = lambda : None)
        elif username is None and email == conn.entries[0]['mail'].values[0]:            
            return Mock(one_or_none = lambda : user)
        else:
            raise RuntimeError('argh')
    
    user_mock = Mock(query = \
                     Mock(filter_by = MagicMock(side_effect = _filter_by)))


    @patch('invenio_ldapclient.views.User', user_mock)
    @patch(
        'invenio_ldapclient.views._register_or_update_user',
        return_value=user
    )
    def assert_returns_user(mocks):
        assert subject(conn, 'itsame') == user

    assert_returns_user()


@patch('invenio_ldapclient.views._search_ldap', lambda x, y: None)
def test_view__find_or_register_inactive_user_found_by_email(app):
    InvenioLDAPClient(app)
    subject = invenio_ldapclient.views._find_or_register_user
    conn = Mock(entries=[{'mail': Mock(values=['itsame@ta.da'])}])
    user = Mock(active=False)

    def _filter_by(username=None, email=None):
        if email is None:
            return Mock(one_or_none = lambda : None)
        elif username is None and email == conn.entries[0]['mail'].values[0]:            
            return Mock(one_or_none = lambda : user)
        else:
            raise RuntimeError('argh')
    
    user_mock = Mock(query = \
                     Mock(filter_by = MagicMock(side_effect = _filter_by)))

    @patch('invenio_ldapclient.views.User', user_mock)
    @patch(
        'invenio_ldapclient.views._register_or_update_user',
        return_value=user
    )
    def assert_returns_none(mocks):
        assert subject(conn, 'itsame') is None

    assert_returns_none()


@patch('invenio_ldapclient.views._search_ldap', lambda x, y: None)
def test_view__find_or_register_not_found_by_username_no_email_filtering(app):
    app.config['LDAPCLIENT_FIND_BY_EMAIL'] = False
    InvenioLDAPClient(app)
    subject = invenio_ldapclient.views._find_or_register_user
    conn = Mock(entries=[{'mail': Mock(values=['itsame@ta.da'])}])
    user = Mock(active=True)
    new_user = Mock()

    def _filter_by(username=None, email=None):
        if email is None:
            return Mock(one_or_none = lambda : None)
        elif username is None and email == conn.entries[0]['mail'].values[0]:            
            return Mock(one_or_none = lambda : user)
        else:
            raise RuntimeError('argh')
    
    user_mock = Mock(query = \
                     Mock(filter_by = MagicMock(side_effect = _filter_by)))

    @patch('invenio_ldapclient.views.User', user_mock)
    @patch(
        'invenio_ldapclient.views._register_or_update_user',
        return_value=new_user
    )
    def assert_returns_new_user(mocks):
        assert subject(conn, 'itsame') == new_user

    assert_returns_new_user()


@patch('invenio_ldapclient.views._search_ldap', lambda x, y: None)
def test_view__find_or_register_user_not_found_no_auto_registration(app):
    app.config['LDAPCLIENT_AUTO_REGISTRATION'] = False
    InvenioLDAPClient(app)
    subject = invenio_ldapclient.views._find_or_register_user
    conn = Mock(entries=[{'mail': Mock(values=['itsame@ta.da'])}])

    def _filter_by(username=None, email=None):
        return Mock(one_or_none = lambda : None)
        
    user_mock = Mock(query = \
                     Mock(filter_by = MagicMock(side_effect = _filter_by)))


    @patch('invenio_ldapclient.views.User', user_mock)
    def assert_returns_none():
        assert subject(conn, 'itsame') is None

    assert_returns_none()

def test_view__search_ldap(app):
    InvenioLDAPClient(app)
    app.config['LDAPCLIENT_SEARCH']['search_base'] = 'ou=base,cn=com'
    app.config['LDAPCLIENT_SEARCH']['username_attribute'] = 'userId'
    subject = invenio_ldapclient.views._search_ldap

    # LDAPCLIENT_SEARCH_ATTRIBUTES is not set
    conn_mock = Mock()
    assert subject(conn_mock, 'itsame') is None
    conn_mock.search.assert_called_once_with(
        'ou=base,cn=com',
        '(userId=itsame)',
        attributes='*'
    )

    # LDAPCLIENT_SEARCH_ATTRIBUTES is set
    app.config['LDAPCLIENT_SEARCH']['search_attributes'] = ['abc', 'bcd']
    conn_mock = Mock()
    assert subject(conn_mock, 'itsame') is None
    conn_mock.search.assert_called_once_with(
        'ou=base,cn=com',
        '(userId=itsame)',
        attributes=['abc', 'bcd']
    )


@patch('uuid.uuid4', lambda: Mock(hex='fancy-pass'))
def test_view__register_or_update_user(app):
    InvenioAccountsUI(app)
    InvenioLDAPClient(app)
    app.config['LDAPCLIENT_SEARCH']['email_attribute'] = 'daMail'
    app.config['LDAPCLIENT_SEARCH']['username_attribute'] = 'daUsername'
    app.config['LDAPCLIENT_SEARCH']['fullname_attribute'] = 'daFullName'
    entries = {
        'daMail': Mock(values=['itsame@ta.da']),
        'daUsername': Mock(values=['itsame']),
        'daFullName': Mock(values=['Itsa Me']),
    }
    subject = invenio_ldapclient.views._register_or_update_user

    # New user
    #up_mock = MagicMock(autospec=UserProfile)
    #with patch('invenio_ldapclient.views.UserProfile', lambda user_id: up_mock):  # noqa
    #    user_mock = Mock(get_id=lambda: '666')
    #    user_class_mock = Mock(
    #        query=Mock(
    #            filter_by=lambda email: Mock(
    #                one_or_none=lambda: user_mock
    #            )
    #        )
    #    )
    #    with patch('invenio_ldapclient.views._datastore') as cu_patch:
    #        with patch('invenio_ldapclient.views.User', user_class_mock):
    #            with patch('invenio_ldapclient.views.db.session.add') as session_patch:  # noqa
    #                assert subject(entries) == user_mock
                
    #assert up_mock.username == 'itsame'
    #assert up_mock.full_name == 'Itsa Me'
    #cu_patch.create_user.assert_called_once_with(
    #    active=True,
    #    email='itsame@ta.da',
    #    password='fancy-pass'
    #)
    #session_patch.assert_called_with(up_mock)

    user_mock = Mock(get_id=lambda: '666')
    user_mock.email = 'itsame@ta.da'

    def _filter_by(username=None, email=None):
        return Mock(one_or_none = lambda : user_mock)

    user_class_mock = Mock(query = \
                           Mock(filter_by = MagicMock(side_effect = _filter_by)))

    @patch('invenio_ldapclient.views.db.session.add')
    @patch('invenio_ldapclient.views._datastore')
    @patch('invenio_ldapclient.views.User', user_class_mock)
    def new_user(mocked__datastore, mocked_db_session_add):
        user_account = subject(entries)

        mocked__datastore.create_user.assert_called_once_with(
            active=True,
            email='itsame@ta.da',
            password='fancy-pass'
        )

        assert user_account.username == 'itsame'
        assert user_account.full_name == 'Itsa Me'
        assert user_account.email == 'itsame@ta.da'
        mocked_db_session_add.assert_called_once_with(user_account)

    # Existing user
    #up_mock2 = MagicMock(autospec=UserProfile)
    #user_mock2 = Mock(autospec=User, profile=up_mock2)
    #with patch('invenio_ldapclient.views._datastore') as cu_patch:
    #    with patch(
    #        'invenio_ldapclient.views.db.session.add'
    #    ) as session_patch:
    #        assert subject(entries, user_account=user_mock2) == user_mock2
    #        assert up_mock2.username == 'itsame'
    #        assert up_mock2.full_name == 'Itsa Me'
    #        assert session_patch.call_args_list[0][0][0] == user_mock2
    #assert session_patch.call_args_list[1][0][0] == up_mock2

    user_mock = Mock()
    user_mock.email = 'itsame@ta.da'
    @patch('invenio_ldapclient.views.db.session.add')
    def existing_user(mocked_db_session_add):
        user_account = subject(entries, user_account = user_mock)
        assert user_account.email == 'itsame@ta.da'
        mocked_db_session_add.assert_called_once_with(user_account)

    new_user()
    existing_user()


def test__security(app):
    """Test security method."""
    InvenioLDAPClient(app)
    app.extensions['security'] = 'ama security'
    subject = invenio_ldapclient.views._security
    assert type(subject) == LocalProxy
    assert subject == 'ama security'


def test__datastore(app):
    """Test datastore method."""
    InvenioLDAPClient(app)
    datastore_mock = Mock()
    app.extensions['security'] = Mock(datastore=datastore_mock)
    subject = invenio_ldapclient.views._datastore
    assert type(subject) == LocalProxy
    assert subject == datastore_mock

def test_blueprint(app):
    """Test blueprint."""
    InvenioLDAPClient(app)
    subject = invenio_ldapclient.views.blueprint
    assert subject.name == 'invenio_ldapclient'
    assert subject.template_folder == 'templates'

def test__commit(app):
    """Test the _commit method."""
    InvenioAccountsUI(app)
    InvenioLDAPClient(app)

    with patch('invenio_ldapclient.views._datastore') as datastore_patch:
        assert invenio_ldapclient.views._commit() is None
        datastore_patch.commit.assert_called_once_with()


@pytest.mark.parametrize('query_parameters, redirect_to', [
    ('?next=/abc', '/abc'),
    ('', '/'),
    ('?next=http://malicious.dangerous', '/'),
    ('?next=%2Fdeposit%2Fnew', '/deposit/new')])
def test_redirect_to_next(query_parameters, redirect_to, app):
    """Test view when LDAP connection is A-OK."""
    app.extensions['security'] = Mock()
    app.config['SECURITY_POST_LOGIN_VIEW'] = '/'
    app.config['WTF_CSRF_ENABLED'] = False
    InvenioLDAPClient(app)

    @patch('invenio_ldapclient.views.db.session.commit', lambda: True)
    @patch('invenio_ldapclient.views.login_user', lambda user, remember: True)
    @patch('invenio_ldapclient.views._find_or_register_user', autospec=True)
    @patch('invenio_ldapclient.views.after_this_request', autospec=True)
    @patch('invenio_ldapclient.views._ldap_connection', autospec=True)
    def assert_redirect(a, b, c):
        response = app.test_client().post(
            "/ldap-login" + query_parameters,
            data=dict(username='itsame', password='good')
        )

        assert response.status_code == 302
        assert response.location == redirect_to

    assert_redirect()

def test__try_server_connection(app):
    _server = {'hostname': 'example2.com',
               'port': 636,
               'use_ssl': True,
               'tls': {
                   'validate': ssl.CERT_NONE,
                   'version': ssl.PROTOCOL_TLSv1}
               }

    app.config.update(LDAPCLIENT_AUTHENTICATION = True,
                      LDAPCLIENT_SERVER_INFO = _server)

    InvenioLDAPClient(app)


@patch('invenio_ldapclient.views.Tls', return_value = 'Instantiated TLS object')
def test__tls_object(mocked_tls):
    CERT_NONE = object()
    PROTOCOL_TLSv1 = object()
    
    kwargs = {'host': 'example.com',
              'port': 636,
              'use_ssl': True,
              'tls': {'validate': CERT_NONE,
                      'version': PROTOCOL_TLSv1}}

    new_kwargs = invenio_ldapclient.views._tls_dict_to_object(kwargs)
    assert mocked_tls.called_with(CERT_NONE, PROTOCOL_TLSv1)
    assert new_kwargs['tls'] == 'Instantiated TLS object'

    mocked_tls.reset_mock(return_value = 'Another instantiated TLS object')

    kwargs = {'host': 'example.com',
              'port': 636,
              'use_ssl': True}

    new_kwargs = invenio_ldapclient.views._tls_dict_to_object(kwargs)

    mocked_tls.assert_not_called()
    assert new_kwargs.get('tls', None) is None



    

    
                    

