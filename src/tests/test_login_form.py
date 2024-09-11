from unittest.mock import Mock, patch

import pytest

from invenio_accounts import InvenioAccountsUI
from flask import request, current_app
from ldap3 import MOCK_SYNC, Connection

from invenio_ldapclient import InvenioLDAPClient
from invenio_ldapclient.forms import login_form_factory

def test_bind(server):
    conn = Connection(server,
                      'uid=testuser0,ou=People,o=Example,dc=example,dc=com',
                      b'secret123',
                      client_strategy=MOCK_SYNC)

    assert conn.bind()


def test_factory_returns_form_subclass(app):
    from invenio_ldapclient.forms import login_form_factory
    from flask_security.forms import Form

    InvenioLDAPClient(app)    
    LoginForm = login_form_factory(app)
    assert hasattr(LoginForm, 'username')
    assert hasattr(LoginForm, 'password')
    assert hasattr(LoginForm, 'submit')
    assert hasattr(LoginForm, 'next')
    assert issubclass(LoginForm, Form)
    

def test_next(app):
    InvenioLDAPClient(app)
    InvenioAccountsUI(app)    

    def inner():
            login_form = login_form_factory(app)()
            assert login_form.next.data == '/where_to_next'

    with app.test_request_context('/login/?next=/where_to_next', method='POST'):
        inner()

def test_no_username_or_password_or_form_not_submitted(app):
    app.config.update(WTF_CSRF_ENABLED = False)
    
    InvenioLDAPClient(app)
    InvenioAccountsUI(app)

    with app.test_request_context(method = 'POST',
                                  data = {'username': 'testuser1'}):

        login_form = login_form_factory(app)()
        assert not login_form.validate()
        assert 'This field is required.' in login_form.errors['password']

    with app.test_request_context(method = 'POST',
                                  data = {'password': 'secret123'}):

        login_form = login_form_factory(app)()
        assert not login_form.validate()
        assert 'This field is required.' in login_form.errors['username']

    with app.test_request_context(method = 'GET',
                                  data = {'username': 'testuser1',
                                          'password': 'secret123'}):

        login_form = login_form_factory(app)()
        assert not login_form.validate()
        assert not login_form.is_submitted()


def test_username_password_invalid(configured_app, server):
    app = configured_app
    mockServerCls = Mock(return_value = server)

    @patch('invenio_ldapclient.ext.Server', mockServerCls)
    def inner():
    
        InvenioLDAPClient(app)
        InvenioAccountsUI(app)
        
        with app.test_request_context(method = 'POST',
                                      data = {'username': 'testuser1',
                                              'password': 'wrongpassword'}):

            login_form = login_form_factory(app)()
            assert login_form.is_submitted()
            assert not login_form.validate()
            assert 'Username and password not valid' in login_form.errors['username']

    inner()

def test_user_not_in_group(configured_app, server):
    app = configured_app
    mockServerCls = Mock(return_value = server)

    @patch('invenio_ldapclient.ext.Server', mockServerCls)
    def inner():

        InvenioLDAPClient(app)
        InvenioAccountsUI(app)
        
        with app.test_request_context(method = 'POST',
                                      data = {'username': 'testuser2',
                                              'password': 'secret123'}):

            login_form = login_form_factory(app)()
            assert login_form.is_submitted()
            assert not login_form.validate()
            assert 'User not in required group(s)' in login_form.errors['username']

    inner()


def test_no_email(configured_app, server):
    app = configured_app
    mockServerCls = Mock(return_value = server)

    @patch('invenio_ldapclient.ext.Server', mockServerCls)
    def inner():
    
        InvenioLDAPClient(app)
        InvenioAccountsUI(app)
        
        with app.test_request_context(method = 'POST',
                                      data = {'username': 'testuser3',
                                              'password': 'secret123'}):

            login_form = login_form_factory(app)()
            assert login_form.is_submitted()
            assert not login_form.validate()
            assert 'User email not registered.' in login_form.errors['username']


    inner()

def test_no_display_name(configured_app, server):
    app = configured_app
    mockServerCls = Mock(return_value = server)

    @patch('invenio_ldapclient.ext.Server', mockServerCls)
    def inner():
    
        InvenioLDAPClient(app)
        InvenioAccountsUI(app)
        
        with app.test_request_context(method = 'POST',
                                      data = {'username': 'testuser4',
                                              'password': 'secret123'}):

            login_form = login_form_factory(app)()
            assert login_form.is_submitted()
            assert login_form.validate()

    inner()    

def test_all_good(configured_app, server):
    app = configured_app
    mockServerCls = Mock(return_value = server)

    @patch('invenio_ldapclient.ext.Server', mockServerCls)
    def inner():
    
        InvenioLDAPClient(app)
        InvenioAccountsUI(app)
        
        with app.test_request_context(method = 'POST',
                                      data = {'username': 'testuser1',
                                              'password': 'secret123'}):

            login_form = login_form_factory(app)()
            assert login_form.is_submitted()
            assert login_form.validate()


    inner()

def test_not_under_search_base(strangely_configured_app, server):
    app = strangely_configured_app
    mockServerCls = Mock(return_value = server)

    @patch('invenio_ldapclient.ext.Server', mockServerCls)
    def inner():
    
        InvenioLDAPClient(app)
        InvenioAccountsUI(app)
        
        with app.test_request_context(method = 'POST',
                                      data = {'username': 'testuser0',
                                              'password': 'secret123'}):

            login_form = login_form_factory(app)()
            
            assert login_form.is_submitted()
            assert not login_form.validate()
            
    inner()
