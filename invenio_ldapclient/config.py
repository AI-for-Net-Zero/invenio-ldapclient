# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Galter Health Sciences Library & Learning Center.
#
# Invenio-LDAPClient is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Invenio v3 LDAP client for authentication and user attributes population."""

LDAPCLIENT_AUTHENTICATION = True
"""Use LDAP as an authentication method without overriding the default."""

LDAPCLIENT_AUTO_REGISTRATION = True
"""Automatically register users and populate their attributes from LDAP."""

LDAPCLIENT_EXCLUSIVE_AUTHENTICATION = True
"""
Set LDAP as the only authentication method, adjust user profile actions,
remove ability to set custom user attributes. Auto-register user.
"""

LDAPCLIENT_USERNAME_PLACEHOLDER = 'Username'
"""Placeholder for the login form username field."""

# LDAPCLIENT_SERVER_HOSTNAME = 'example.com'
"""LDAP server hostname."""

LDAPCLIENT_SERVER_PORT = 389
"""LDAP server port."""

LDAPCLIENT_USE_SSL = False
"""Use SSL for LDAP connection."""

LDAPCLIENT_USE_TLS = False
"""Use TLS for LDAP connection."""

# LDAPCLIENT_ADMIN_ACCOUNT = 'uid=admin,ou=people,dc=example,dc=com'
"""
Admin LDAP account used for searching. If not set the authenticating
user account will be used.
"""

# LDAPCLIENT_ADMIN_PASSWORD = 'NOTIT'
"""Admin LDAP account password."""

# LDAPCLIENT_SEARCH_BASE = 'dc=example,dc=com'
"""Base for binding to LDAP."""

# LDAPCLIENT_BIND_BASE = 'ou=people,dc=example,dc=com'
"""Base for binding to LDAP."""

LDAPCLIENT_USERNAME_ATTRIBUTE = 'uid'
"""
Username LDAP attribute.
Appended to `LDAPCLIENT_BIND_BASE` with the username from the log-in form
for binding. For example:

    uid=FORM-USERNAME,ou=people,dc=example,dc=com
"""

LDAPCLIENT_EMAIL_ATTRIBUTE = 'mail'
"""Email LDAP attribute."""

LDAPCLIENT_FULL_NAME_ATTRIBUTE = 'displayName'
"""Full name LDAP attribute."""

LDAPCLIENT_SEARCH_ATTRIBUTES = [
    LDAPCLIENT_USERNAME_ATTRIBUTE,
    LDAPCLIENT_EMAIL_ATTRIBUTE,
    LDAPCLIENT_FULL_NAME_ATTRIBUTE
]
"""Attributes to fetch from LDAP."""
