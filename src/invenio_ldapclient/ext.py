# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Galter Health Sciences Library & Learning Center.
#
# Invenio-LDAPClient is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Invenio v3 LDAP client for authentication and user attributes population."""

from __future__ import absolute_import, print_function

from flask import Blueprint

from . import config

# from .views import create_blueprint, login_via_ldap
from .utils import config_value as cv
from ldap3 import Server, ServerPool


class _LDAPServers:
    def __init__(self, server_kwargs, server_pool_kwargs=None):
        """hosts is either tuple[str, int], tuple[str] or iterable of either of these
        server_kwargs is either dict or iter[dict]"""

        if isinstance(server_kwargs, dict):
            server = Server(**server_kwargs)
            server_pool = None
        else:
            server_pool_kwargs = server_pool_kwargs or {}
            servers = [Server(**kws) for kws in server_kwargs]
            server_pool = ServerPool(servers, **server_pool_kwargs)

        self.servers = server_pool if server_pool else server


class InvenioLDAPClient(object):
    """Invenio-LDAPClient extension."""

    def __init__(self, app=None):
        """Extension initialization."""
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.init_config(app)

        if not cv("exclusive_authentication", app):
            raise NotImplementedError("LDAP must be sole auth mechanism")

        server_kwargs = cv("server_kwargs", app)
        if server_kwargs:
            state = _LDAPServers(
                server_kwargs=server_kwargs,
                server_pool_kwargs=cv("server_pool_kwargs", app),
            )
        else:
            raise RuntimeError("invenio-ldapclient: LDAP server info not provided")

        app.extensions["invenio-ldapclient"] = state

        app.config["SECURITY_CONFIRMABLE"] = False
        app.config["SECURITY_RECOVERABLE"] = False
        app.config["SECURITY_REGISTERABLE"] = False
        app.config["SECURITY_CHANGEABLE"] = False
        app.config["USERPROFILES_EMAIL_ENABLED"] = False

    def init_config(self, app):
        for k in dir(config):
            if k.startswith("LDAPCLIENT_"):
                app.config.setdefault(k, getattr(config, k))


class InvenioLDAPClientUI(InvenioLDAPClient):
    def init_app(self, app):
        """Flask application initialization."""
        from .views import login_ldap_ui
        super(InvenioLDAPClientUI, self).init_app(app)

        # Set invenio_accounts login-view config option
        # ... config, view-function, template ...what else?
        app.config["ACCOUNTS_LOGIN_VIEW_FUNCTION"] = login_ldap_ui
        app.config["ACCOUNTS_BASE_TEMPLATE"] = cv("base_template", app)
        app.config["ACCOUNTS_COVER_TEMPLATE"] = cv("cover_template", app)

        # Registering blueprint to add templates to search path
        bp = Blueprint("invenio-ldapclient-ui", __name__, template_folder="templates")
        app.register_blueprint(bp)

    def init_config(self, app):
        """Initialize configuration."""
        super(InvenioLDAPClientUI, self).init_config(app)
        
        if "COVER_TEMPLATE" in app.config:
            app.config.setdefault(
                "LDAPCLIENT_BASE_TEMPLATE",
                app.config["COVER_TEMPLATE"],
            )        

class InvenioLDAPClientREST(InvenioLDAPClient):
    def init_app(self, app):
        """Flask application initialization."""

        super(InvenioLDAPClientREST, self).init_app(app)

        #stop InvenioAccounts.init_app adding "security.login" to app.view_functions
        app.config["ACCOUNTS_LOGIN_VIEW_FUNCTION"] = None
        
        app.config["ACCOUNTS_REST_AUTH_VIEWS"] = {
            "login": "invenio_ldapclient.views_rest:LoginView",
            "logout": "invenio_accounts.views.rest:LogoutView",
            "user_info": "invenio_accounts.views.rest:UserInfoView",
            "register": "invenio_accounts.views.rest:RegisterView",
            "forgot_password": "invenio_accounts.views.rest:ForgotPasswordView",
            "reset_password": "invenio_accounts.views.rest:ResetPasswordView",
            "change_password": "invenio_accounts.views.rest:ChangePasswordView",
            "send_confirmation": "invenio_accounts.views.rest:SendConfirmationEmailView",
            "confirm_email": "invenio_accounts.views.rest:ConfirmEmailView",
            "sessions_list": "invenio_accounts.views.rest:SessionsListView",
            "sessions_item": "invenio_accounts.views.rest:SessionsItemView",
        }


