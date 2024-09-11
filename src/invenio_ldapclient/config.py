# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Galter Health Sciences Library & Learning Center.
#
# Invenio-LDAPClient is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Invenio v3 LDAP client for authentication and user attributes population.

In your instance's ``config.py`` or via other means, you MUST override the
following configuration:

.. code-block:: python

    LDAPCLIENT_SERVER_HOSTNAME = '<your ldap hostname>'
    LDAPCLIENT_SEARCH_BASE = '<your ldap search base>'
    LDAPCLIENT_BIND_BASE = '<your base binding to LDAP>'

Below is a list of all configuration variables:
"""
from ldap3 import ROUND_ROBIN

LDAPCLIENT_AUTHENTICATION = True
"""Use LDAP as an authentication method without overriding the default."""

LDAPCLIENT_FIND_BY_EMAIL = True
"""Allow looking users up by email if not found by username."""

LDAPCLIENT_REQUIRE_HTTPS = False
"""When checking redirect in views.ldap_login"""

LDAPCLIENT_AUTO_REGISTRATION = True
"""Automatically register users and populate their attributes from LDAP."""

LDAPCLIENT_EXCLUSIVE_AUTHENTICATION = True
"""
Set LDAP as the only authentication method, adjust user profile actions,
remove ability to set custom user attributes. Auto-register user.
"""

LDAPCLIENT_LOGIN_USER_TEMPLATE = 'invenio_ldapclient/login_user.html'
"""LDAP login template."""

LDAPCLIENT_USERNAME_PLACEHOLDER = 'Username'
"""Placeholder for the login form username field."""


LDAPCLIENT_SERVER_POOL = True
"""
Are we forming a server pool?  If so, pass iterables of hosts and (possibly also) kwargs - 
see below
"""

LDAPCLIENT_HOSTS = [('ldap.0.example.com', 389), ('ldap://ldap.1.example.com:389',),]
"""
2-tuple of host-port pair passed as 1st & 2nd args to ldap3.Server, or ...

1-tuple with single uri in form <scheme>://<hostname>:<hostport>, where <scheme> is ldap, ldaps 
or ldapi, or ...

iterables of these if using server pool
"""

LDAPCLIENT_SERVER_KWARGS = {'use_ssl': False, 'tls': None}
"""
Dict of kwargs to pass to ldap3.Server, or iterable of such if these differ by server (in which case
MUST NOT be shorter than LDAPCLIENT_HOSTS.  Pass a nested dict of kwargs under 'tls' key to construct Tls object
"""

LDAPCLIENT_CONN_KWARGS = None
"""
None or dict of kwargs passed to ldap3.Connection constructor
"""

LDAPCLIENT_SERVER_POOL_KWARGS = {'pool_strategy': ROUND_ROBIN,
                                 'active': True,
                                 'exhaust': False,
                                 'single_state': True}
"""
These are passed to ServerPool constructor, if LDAPCLIENT_SERVER_POOL is True
"""
                                 

LDAPCLIENT_CUSTOM_CONNECTION = None
"""
Your own lambda for ldap3's Connection. If you need a custom connection
pass it as a lambda that takes a username and a password and returns an
initialized Connection.

For example:

.. code-block:: python

    LDAPCLIENT_CUSTOM_CONNECTION = lambda user, password: Connection(...)

"""

# TODO later
# LDAPCLIENT_ADMIN_ACCOUNT = 'uid=admin,ou=people,dc=example,dc=com'
"""
Admin LDAP account used for searching. If not set, the authenticating
user account will be used.
"""

# TODO later
# LDAPCLIENT_ADMIN_PASSWORD = 'NOTIT'
"""Admin LDAP account password."""

LDAPCLIENT_BIND_BASE = 'ou=people,dc=example,dc=com'
"""Base for binding to LDAP. Your application MUST override this."""


LDAPCLIENT_SEARCH_BASE = 'dc=example,dc=com'
"""Base for binding to LDAP. Your application MUST override this."""

LDAPCLIENT_SEARCH_FILTER = None


LDAPCLIENT_USERNAME_ATTRIBUTE = 'uid'
"""
Username LDAP attribute.
Prepended to ``LDAPCLIENT_BIND_BASE`` with the username from the log in form
for binding, resulting in:

    ``uid=FORM-USERNAME,ou=people,dc=example,dc=com``
"""

LDAPCLIENT_EMAIL_ATTRIBUTE = 'mail'
"""Email LDAP attribute."""

LDAPCLIENT_FULL_NAME_ATTRIBUTE = 'displayName'
"""Full name LDAP attribute."""

LDAPCLIENT_SEARCH_ATTRIBUTES = None
"""List of attributes to fetch from LDAP. Defaults to all of them (``'*'``)."""

LDAPCLIENT_GROUP_FILTERS = []
