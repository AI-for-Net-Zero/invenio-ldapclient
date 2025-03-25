# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Galter Health Sciences Library & Learning Center.
#
# Invenio-LDAPClient is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Invenio v3 LDAP client for authentication and user attributes population.

Below is a list of all configuration variables:
"""

LDAPCLIENT_AUTHENTICATION = None
"""
.. versionremoved:: 2.0.0
"""

LDAPCLIENT_FIND_BY_EMAIL = None
"""
.. versionremoved:: 2.0.0 Searches directory by username only
"""

LDAPCLIENT_REQUIRE_HTTPS = None
"""
.. versionremoved:: 2.0.0
"""

LDAPCLIENT_AUTO_REGISTRATION = None
"""
.. versionremoved:: 2.0.0
"""

LDAPCLIENT_EXCLUSIVE_AUTHENTICATION = True
"""
Authentication via multiple methods not currently supported.

:raises NotImplementedError: when this setting does not evaluate to ``True``
"""

LDAPCLIENT_BASE_TEMPLATE = "invenio_ldapclient/invenio_accounts/base.html"
"""
Base login template.
"""

LDAPCLIENT_COVER_TEMPLATE = "invenio_ldapclient/invenio_accounts/base_cover.html"
"""
Base cover template.
"""

LDAPCLIENT_LOGIN_USER_TEMPLATE = "invenio_ldapclient/login_user.html"
"""
LDAP login template.
"""

LDAPCLIENT_USERNAME_PLACEHOLDER = "Username"
"""
Placeholder for the login form username field.
"""

LDAPCLIENT_SERVER_KWARGS = None
"""
See documentation for ldap3.Server at https://ldap3.readthedocs.io/en/latest/server.html

dict of keyword args to pass to ldap3.Server constructor for a single server
OR an iterable of such to construct a server pool 

E.g., specifying host and port separately

.. code-block:: python

	LDAPCLIENT_SERVER_KWARGS = {'host': 'ldap.0.example.com',
        	                    'port': 389,
                	            'use_ssl': False}

or letting ldap3 infer the port from the uri

.. code-block:: python

	LDAPCLIENT_SERVER_KWARGS = {'host': 'ldaps://ldap.1.example.com',
        	                    'use_ssl': True,
                	            'tls': <Some custom Tls object (see documentation)>}

or a list telling invenio-ldapclient to construct a server pool of 2 server instances
                        
.. code-block:: python

	LDAPCLIENT_SERVER_KWARGS = [{'host': 'ldap.0.example.com',
        	                     'port': 389,
                	             'use_ssl': False},
                        	    {'host': 'ldap.1.example.com',
                             	     'port': 389,
                             	     'use_ssl': False}]  
"""

LDAPCLIENT_SERVER_POOL_KWARGS = None
"""
Passed to ``ldap3.ServerPool`` constuctor - see `<https://ldap3.readthedocs.io/en/latest/server.html>`_

These are passed to 

.. code-block:: python

	LDAPCLIENT_SERVER_POOL_KWARGS = {'pool_strategy': ldap3.ROUND_ROBIN,
        	                         'active': True,
                	                 'exhaust': False,
                        	         'single_state': True}
"""

LDAPCLIENT_CONNECTION_KWARGS = None
"""
None or dict of remaining keyword args to pass to ldap3.Connection constructor after 
server, user, password, which are passed by the implementation

See docs at `<https://ldap3.readthedocs.io/en/latest/connection.html>`_
"""

LDAPCLIENT_USER_SEARCH_BASE = None
"""
str

Passed to ``ldap.Connection.search`` as ``search_base`` parameter when searching DIT for user
"""


LDAPCLIENT_USER_SEARCH_FILTER = None
"""
Must set this

Callable[[str],str]

Takes login_form.username and returns str to pass to
ldap3.Connection.search as search_filter argument when searching DIT for user

E.g.,

.. code-block:: python

	LDAPCLIENT_USER_SEARCH_FILTER =
		lambda username : f'(&(uid={username})(objectClass=posixAccount))'
"""

LDAPCLIENT_USER_SEARCH_KWARGS = None
"""
dict of remaining keyword args to pass to ldap3.Connection.search

E.g., 

.. code-block:: python

	LDAPCLIENT_USER_SEARCH_KWARGS = {attributes: ldap3.ALL_ATTRIBUTES}
"""

LDAPCLIENT_EMAIL_ATTRIBUTE = "mail"
"""Email LDAP attribute."""

LDAPCLIENT_FULL_NAME_ATTRIBUTE = "displayName"
"""Full name LDAP attribute."""

LDAPCLIENT_GROUP_SEARCH_BASE = None
"""
str

Passed to ``ldap.Connection.search`` as ``search_base`` parameter when searching DIT for groups
"""

LDAPCLIENT_GROUP_SEARCH_FILTERS = None
"""
iter[Callable[[str],str]]

each callable takes login_form.username and return str to pass to
ldap3.Connection.search as search_filter argument when searching DIT for group with user as 
member

E.g.,

.. code-block:: python

	LDAPCLIENT_GROUP_FILTERS = \
		[lambda u : f'(&(memberUid={u})(objectClass=posixGroup)(cn=group1))',
                 lambda u : f'(&(memberUid={u})(objectClass=posixGroup)(cn=group2))']


If ``None``, disallow authentication attempts
"""

ACCOUNTS_REST_AUTH_VIEWS = {
    "login": "invenio_ldapclient.views.rest:LoginView",
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
"""
Sets login view to ldap for REST API applications
"""

LDAPCLIENT_TEMPORARY_EMAIL_FIX = False
"""
If directory search does not return an email address, authentication fails.  To disable this, set this to True and an email address will be constructed as <username>"@"LDAPCLIENT_TEMPORARY_EMAIL_FIX_DOMAIN
"""

LDAPCLIENT_TEMPORARY_EMAIL_FIX_DOMAIN = None
"""
If 

.. code-block:: python

	LDAPCLIENT_TEMPORARY_EMAIL_FIX = True, provide the domain here.
"""
