from unittest.mock import patch, Mock, MagicMock

import pytest
from ldap3 import ServerPool

from invenio_accounts import InvenioAccountsUI, InvenioAccountsREST
from invenio_accounts.views.rest import create_blueprint
from invenio_ldapclient import InvenioLDAPClient, InvenioLDAPClientREST, InvenioLDAPClientUI
from invenio_ldapclient.views import login_ldap_ui
from invenio_ldapclient.views_rest import LoginView
    
def test_login_view_fn(initialised_UI_app):
    app = initialised_UI_app

    assert "security" in app.extensions
    assert "ACCOUNTS_LOGIN_VIEW_FUNCTION" in app.config

    assert app.config["ACCOUNTS_LOGIN_VIEW_FUNCTION"] is login_ldap_ui
    assert app.login_manager is app.extensions["security"].login_manager
    assert app.login_manager.login_view == "security.login"
    assert app.view_functions["security.login"] is login_ldap_ui


def test_security_config(initialised_UI_app):
    app = initialised_UI_app

    assert app.config["SECURITY_CONFIRMABLE"] is False
    assert app.config["SECURITY_RECOVERABLE"] is False
    assert app.config["SECURITY_REGISTERABLE"] is False
    assert app.config["SECURITY_CHANGEABLE"] is False
    assert app.config["USERPROFILES_EMAIL_ENABLED"] is False


def test_server_pool(configured_app_with_server_pool):
    app = configured_app_with_server_pool

    assert type(app.extensions["invenio-ldapclient"].servers) is ServerPool

def test_invenio_ldapclient_rest(initialised_REST_app):
    app = initialised_REST_app

    assert app.config["SECURITY_CONFIRMABLE"] is False
    assert app.config["SECURITY_RECOVERABLE"] is False
    assert app.config["SECURITY_REGISTERABLE"] is False
    assert app.config["SECURITY_CHANGEABLE"] is False
    assert app.config["USERPROFILES_EMAIL_ENABLED"] is False

    assert app.config["ACCOUNTS_REST_AUTH_VIEWS"]["login"] == "invenio_ldapclient.views_rest:LoginView"

def test_ui_non_excl(configured_app):
    app = configured_app
    app.config["LDAPCLIENT_EXCLUSIVE_AUTHENTICATION"] = False

    with pytest.raises(NotImplementedError, match = "LDAP must be sole auth mechanism"):
        InvenioLDAPClientUI(app)

    
def test_rest_non_excl(configured_app):
    app = configured_app
    app.config["LDAPCLIENT_EXCLUSIVE_AUTHENTICATION"] = False

    with pytest.raises(NotImplementedError, match = "LDAP must be sole auth mechanism"):
        InvenioLDAPClientREST(app)

def test_no_server_info(configured_app):
    app = configured_app
    del app.config["LDAPCLIENT_SERVER_KWARGS"]

    with pytest.raises(RuntimeError, match = "invenio-ldapclient: LDAP server info not provided"):
        InvenioLDAPClient(app)

def test_rest_view_fns(initialised_REST_app):
    app = initialised_REST_app

    app.register_blueprint(create_blueprint(app))

    assert "invenio_accounts_rest_auth.login" in app.view_functions
    view_fn = app.view_functions["invenio_accounts_rest_auth.login"]
    assert view_fn.__module__ == "invenio_ldapclient.views_rest"

    assert "invenio_accounts_rest_auth.logout" in app.view_functions
    view_fn = app.view_functions["invenio_accounts_rest_auth.logout"]
    assert view_fn.__module__ == "invenio_accounts.views.rest"

    assert "invenio_accounts_rest_auth.user_info" in app.view_functions
    view_fn = app.view_functions["invenio_accounts_rest_auth.user_info"]
    assert view_fn.__module__ == "invenio_accounts.views.rest"

    
    
