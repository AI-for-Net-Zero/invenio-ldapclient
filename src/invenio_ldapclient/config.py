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

LDAPCLIENT_BASE_TEMPLATE = 'invenio_ldapclient/invenio_accounts/base.html'
LDAPCLIENT_COVER_TEMPLATE = 'invenio_ldapclient/invenio_accounts/base_cover.html'
LDAPCLIENT_LOGIN_USER_TEMPLATE = 'invenio_ldapclient/login_user.html'
"""LDAP login template."""

LDAPCLIENT_USERNAME_PLACEHOLDER = 'Username'
"""Placeholder for the login form username field."""

LDAPCLIENT_SERVER_KWARGS = None
"""
See documentation for ldap3.Server at https://ldap3.readthedocs.io/en/latest/server.html

dict of keyword args to pass to ldap3.Server constructor for a single server
OR an iterable of such to construct a server pool 

E.g., specifying host and port separately
LDAPCLIENT_SERVER_KWARGS = {'host': 'ldap.0.example.com',
                            'port': 389,
                            'use_ssl': False}

or letting ldap3 infer the port from the uri

LDAPCLIENT_SERVER_KWARGS = {'host': 'ldaps://ldap.1.example.com',
                            'use_ssl': True,
                            'tls': <Some custom Tls object (see documentation)>}

or a list telling invenio-ldapclient to construct a server pool of 2 server instances
                        
LDAPCLIENT_SERVER_KWARGS = [{'host': 'ldap.0.example.com',
                            'port': 389,
                            'use_ssl': False},
                            {'host': 'ldap.1.example.com',
                             'port': 389,
                             'use_ssl': False}]  
"""

LDAPCLIENT_SERVER_POOL_KWARGS = None
"""
See documentation for ldap3.ServerPool at https://ldap3.readthedocs.io/en/latest/server.html 

dict of keyword args excluding servers to pass to ldap3.ServerPool constructor (if using) 
E.g.,
LDAPCLIENT_SERVER_POOL_KWARGS = {'pool_strategy': ldap3.ROUND_ROBIN,
                                 'active': True,
                                 'exhaust': False,
                                 'single_state': True}
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

LDAPCLIENT_CONNECTION_KWARGS = None
"""
None or dict of remaining keyword args to pass to ldap3.Connection constructor after 
server, user, password, which are passed by the implementation

See docs at https://ldap3.readthedocs.io/en/latest/connection.html
"""

LDAPCLIENT_USER_SEARCH_BASE = None
"""
str

Passed to ldap.Connection.search as search_base parameter when searching DIT for user
"""


LDAPCLIENT_USER_SEARCH_FILTER = None
"""
Must set this

Callable[[str],str]

Takes login_form.username and returns str to pass to
ldap3.Connection.search as search_filter argument when searching DIT for user

E.g.,
LDAPCLIENT_USER_SEARCH_FILTER = lambda username : f'(&(uid={username})(objectClass=posixAccount))'
"""

LDAPCLIENT_USER_SEARCH_KWARGS = None
"""
dict of remaining keyword args to pass to ldap3.Connection.search

E.g.,
LDAPCLIENT_USER_SEARCH_KWARGS = {attributes: ldap3.ALL_ATTRIBUTES}
"""

LDAPCLIENT_EMAIL_ATTRIBUTE = 'mail'
"""Email LDAP attribute."""

LDAPCLIENT_FULL_NAME_ATTRIBUTE = 'displayName'
"""Full name LDAP attribute."""

LDAPCLIENT_GROUP_SEARCH_BASE = None
"""
str

Passed to ldap.Connection.search as search_base parameter when searching DIT for groups
"""

LDAPCLIENT_GROUP_SEARCH_FILTERS = None
"""
iter[Callable[[str],str]]

each callable takes login_form.username and return str to pass to
ldap3.Connection.search as search_filter argument when searching DIT for group with user as 
member

E.g.,
LDAPCLIENT_GROUP_FILTERS = [lambda u : f'(&(memberUid={u})(objectClass=posixGroup)(cn=group1))',
                            lambda u : f'(&(memberUid={u})(objectClass=posixGroup)(cn=group2))']

If None, disallow all
"""





