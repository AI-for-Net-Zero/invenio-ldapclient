# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Galter Health Sciences Library & Learning Center.
#
# Invenio-LDAPClient is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Invenio v3 LDAP client for authentication and user attributes population."""

from __future__ import absolute_import, print_function

from . import config
from .views import create_blueprint, login_via_ldap
from .utils import get_config, config_value as cv
from ldap3 import Server, ServerPool

class _LDAPServers:
    def __init__(self,                
                 server_kwargs,
                 server_pool_kwargs = None):
        """ hosts is either tuple[str, int], tuple[str] or iterable of either of these
        server_kwargs is either dict or iter[dict] """

        if isinstance(server_kwargs, dict): 
            server = Server(**server_kwargs)
            server_pool = None
        else:
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
        """Flask application initialization."""
        self.init_config(app)

        state = _LDAPServers(server_kwargs = cv('server_kwargs', app),                            
                             server_pool_kwargs = cv('server_pool_kwargs', app))
                             
        if cv('exclusive_authentication'):
            # Set invenio_accounts login-view config option
            # ... config, view-function, template ...what else? 
            app.config['SECURITY_CONFIRMABLE'] = False
            app.config['SECURITY_RECOVERABLE'] = False
            app.config['SECURITY_REGISTERABLE'] = False
            app.config['SECURITY_CHANGEABLE'] = False
            app.config['USERPROFILES_EMAIL_ENABLED'] = False
            app.config['ACCOUNTS_LOGIN_VIEW_FUNCTION'] = login_via_ldap
        else:
            raise NotImplementedError
            #blueprint = create_blueprint(app)
            #register_blueprint
        
        app.extensions['invenio-ldapclient'] = state

    def init_config(self, app):
        """Initialize configuration."""
        if 'COVER_TEMPLATE' in app.config:
            app.config.setdefault(
                'LDAPCLIENT_BASE_TEMPLATE',
                app.config['COVER_TEMPLATE'],
            )

        for k in dir(config):
            if k.startswith('LDAPCLIENT_'):
                app.config.setdefault(k, getattr(config, k))
