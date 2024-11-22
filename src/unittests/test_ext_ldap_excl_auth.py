from invenio_accounts import InvenioAccountsUI
from invenio_ldapclient import InvenioLDAPClientUI

def test_login_view_fn(configured_app):
    app = configured_app

    InvenioLDAPClientUI(app)
    InvenioAccountsUI(app)

    assert 'security' in app.extensions
    assert 'ACCOUNTS_LOGIN_VIEW_FUNCTION' in app.config

    from invenio_ldapclient.views import login_via_ldap
    assert app.config['ACCOUNTS_LOGIN_VIEW_FUNCTION'] is login_via_ldap
    assert app.login_manager is app.extensions['security'].login_manager
    assert app.login_manager.login_view == 'security.login'
    assert app.view_functions['security.login'] is login_via_ldap

def test_security_config(configured_app):
    app = configured_app

    InvenioLDAPClientUI(app)
    InvenioAccountsUI(app)

    assert app.config['SECURITY_CONFIRMABLE'] is False
    assert app.config['SECURITY_RECOVERABLE'] is False
    assert app.config['SECURITY_REGISTERABLE'] is False
    assert app.config['SECURITY_CHANGEABLE'] is False
    assert app.config['USERPROFILES_EMAIL_ENABLED'] is False

def test_server_pool(configured_app_with_server_pool):
    from ldap3 import Server, ServerPool
    
    app = configured_app_with_server_pool

    InvenioLDAPClientUI(app)
    InvenioAccountsUI(app)

    assert type(app.extensions['invenio-ldapclient'].servers) is ServerPool


'''
invenio_accounts.views.settings:blueprint reg'd on app via entrypoint gp invenio_base.blueprints

invenio_accounts.views.login decorated with this blueprint, route "/login"

blueprint reg triggers
   invenio_accounts.views.settings.post_ext_init
and
   invenio_accounts.views.settings.init_menu




'''
