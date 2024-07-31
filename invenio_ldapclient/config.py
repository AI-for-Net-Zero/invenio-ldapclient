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

LDAPCLIENT_REQUIRE_HTTPS = True

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

LDAPCLIENT_SERVER_INFO = [{'hostname': 'example.com',
                           'port': 389,
                           'use_ssl': True,
                           'tsl': dict(),
                           'groups': None}]
""" 
List of dicts containing at least the keys hostname, port & use_ssl.  When a list
is supplied, connection.bind() is tested sequentially.  If use_ssl = True, TLS options should
be passed as nested dict.  Test membership of groups (list), per-server.
"""


#LDAPCLIENT_SERVER_HOSTNAME = 'example.com'
#"""LDAP server hostname. Your application MUST override this."""

#LDAPCLIENT_SERVER_PORT = 389
#"""LDAP server port."""

#LDAPCLIENT_USE_SSL = False
#"""Use SSL for LDAP connection."""

#LDAPCLIENT_TLS = None
#"""TLS options for LDAP connection server."""

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

LDAPCLIENT_SEARCH_BASE = 'dc=example,dc=com'
"""Base for binding to LDAP. Your application MUST override this."""

LDAPCLIENT_BIND_BASE = 'ou=people,dc=example,dc=com'
"""Base for binding to LDAP. Your application MUST override this."""

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
