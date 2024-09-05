# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Galter Health Sciences Library & Learning Center.
#
# Invenio-LDAPClient is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Invenio v3 LDAP client for authentication and user attributes population."""

from __future__ import absolute_import, print_function

from . import config
from .views import blueprint
from .utils import get_config, _tls_dict_to_object, config_value as cv
from ldap3 import Server, ServerPool

#self.servers = server_cls


#servers = 
#server_pool = ServerPool(servers, ROUND_ROBIN, active=True, exhaust=True)


class _LDAPServers:
    def __init__(self,
                 hosts,
                 server_kwargs,
                 server_pool,
                 server_pool_kwargs = None):
        # hosts is either tuple[str, int], tuple[str] or iterable of either of these
        # server_kwargs is either dict or iter[dict]

        if not server_pool:
            self.servers = Server(*hosts, **_tls_dict_to_object(server_kwargs))
        else:
            if isinstance(server_kwargs, dict): 
                self.servers = ServerPool([ Server(*h, **_tls_dict_to_object(server_kwargs)) \
                                            for h in hosts ], **server_pool_kwargs)

            else:
                self.servers = ServerPool([ Server(*h, **_tls_dict_to_object(kws)) \
                                            for h, kws in zip(hosts, server_kwargs)],
                                          **server_pool_kwargs)

            
                

class InvenioLDAPClient(object):
    """Invenio-LDAPClient extension."""

    def __init__(self, app=None):
        """Extension initialization."""
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Flask application initialization."""
        self.init_config(app)

        state = _LDAPServers(hosts = cv('hosts', app),
                             server_kwargs = cv('server_kwargs', app),
                             server_pool = cv('server_pool', app),
                             server_pool_kwargs = cv('server_pool_kwargs', app))
                             
        
        app.register_blueprint(blueprint)
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
                '''
                dict instances are mutable. Copy, o/w unit tests will mutate .config
                '''
                if isinstance( getattr(config, k), dict):
                    app.config.setdefault(k, getattr(config, k).copy() )
                else:
                    app.config.setdefault(k, getattr(config, k))

        if not app.config['LDAPCLIENT_AUTHENTICATION']:
            return

        if app.config['LDAPCLIENT_EXCLUSIVE_AUTHENTICATION']:
            @app.before_first_request
            def ldap_login_view_setup():
                from .views import ldap_login
                app.view_functions['security.login'] = ldap_login
                app.extensions['security'].login_manager.login_view = \
                    'invenio_ldapclient.ldap_login'
                app.config['SECURITY_CONFIRMABLE'] = False
                app.config['SECURITY_RECOVERABLE'] = False
                app.config['SECURITY_REGISTERABLE'] = False
                app.config['SECURITY_CHANGEABLE'] = False
                app.config['USERPROFILES_EMAIL_ENABLED'] = False

            app.config['SECURITY_LOGIN_USER_TEMPLATE'] = (
                app.config['LDAPCLIENT_LOGIN_USER_TEMPLATE']
            )
