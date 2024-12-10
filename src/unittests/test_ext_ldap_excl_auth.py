def test_login_view_fn(configured_app):
    app = configured_app

    assert "security" in app.extensions
    assert "ACCOUNTS_LOGIN_VIEW_FUNCTION" in app.config

    from invenio_ldapclient.views import login_ldap_ui

    assert app.config["ACCOUNTS_LOGIN_VIEW_FUNCTION"] is login_ldap_ui
    assert app.login_manager is app.extensions["security"].login_manager
    assert app.login_manager.login_view == "security.login"
    assert app.view_functions["security.login"] is login_ldap_ui


def test_security_config(configured_app):
    app = configured_app

    assert app.config["SECURITY_CONFIRMABLE"] is False
    assert app.config["SECURITY_RECOVERABLE"] is False
    assert app.config["SECURITY_REGISTERABLE"] is False
    assert app.config["SECURITY_CHANGEABLE"] is False
    assert app.config["USERPROFILES_EMAIL_ENABLED"] is False


def test_server_pool(configured_app_with_server_pool):
    from ldap3 import ServerPool

    app = configured_app_with_server_pool

    assert type(app.extensions["invenio-ldapclient"].servers) is ServerPool


"""
invenio_accounts.views.settings:blueprint reg'd on app via entrypoint gp invenio_base.blueprints

invenio_accounts.views.login decorated with this blueprint, route "/login"

blueprint reg triggers
   invenio_accounts.views.settings.post_ext_init
and
   invenio_accounts.views.settings.init_menu




"""
