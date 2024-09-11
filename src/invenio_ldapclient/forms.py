# -*- coding: utf-8 -*-
"""Login form for ldap."""

from __future__ import absolute_import, print_function

from flask import Markup, request, current_app
from flask_security.forms import Form, NextFormMixin
from flask_security.utils import url_for_security, hash_password
from wtforms import PasswordField, StringField, SubmitField, validators

from .utils import ldap_connection, check_group_memberships, ldap_search

from ldap3.core.exceptions import LDAPBindError, LDAPKeyError
'''
def login_form_factory(app):
    """Hack to be able to pass current_app into the form."""
    class LoginForm(Form):
        """LDAP login form."""

        username = StringField(
            app.config['LDAPCLIENT_USERNAME_PLACEHOLDER'],
            validators=[validators.InputRequired()]
        )
        password = PasswordField(
            'Password',
            validators=[validators.InputRequired()]
        )

    return LoginForm
'''

def login_form_factory(app):
    """Inserts e.g., current_app, into local namespace of form class"""
    class LoginForm(Form, NextFormMixin):
        """LDAP login form."""

        username = StringField(
            app.config['LDAPCLIENT_USERNAME_PLACEHOLDER'],
            validators=[validators.InputRequired()]
        )
        password = PasswordField(
            'Password',
            validators=[validators.InputRequired()]
        )
        submit = SubmitField('Login')

        def __init__(self, *args, **kwargs):
            super(LoginForm, self).__init__(*args, **kwargs)
            if not self.next.data:
                self.next.data = request.args.get('next', '')
                
            if current_app.extensions['security'].recoverable and \
               not self.password.description:
                html = Markup(u'<a href="{url}">{message}</a>'.format(
                url=url_for_security("forgot_password"),
                message="FORGOT_PASSWORD",
            ))
                self.password.description = html


        def validate(self, extra_validators=None):
            if not super(LoginForm, self).validate(extra_validators=extra_validators):
                return False

            validate_form_and_get_user(self)
            
            if not self.bind:
                self.username.errors.append('Username and password not valid')
                hash_password(self.password.data)
                return False

            if not self.group:
                self.username.errors.append('User not in required group(s)')
                return False

            if not self.email:
                self.username.errors.append('User email not registered.')
                return False
            
            return True

    return LoginForm


def validate_form_and_get_user(login_form):
    """1. run superclass's validators, quit on failure, otherwise
       
       <----- in .utils.ldap_connection &  .utils.ldap_search
       2. get a connection
         - set bind attrib - if fails, return
       3. iterate through groups, checking for membership
         - set group to True if at username belongs to at least one, False otherwise
         - if False, unbind connection, return
       4. call ldap search, getting configured search attribs, set email & full_name
          return
       ------>
     """
    login_form.bind = None
    login_form.group = None
    login_form.email = None
    login_form.full_name = None

    try:
        with ldap_connection(login_form) as connection:
            login_form.bind = True
            
            check_group_memberships(login_form, connection)
            if login_form.group is False:
                return

            ldap_search(connection, login_form.username.data)

            try:
                entries = connection.entries[0]
            
            except IndexError:
                return

            try:
                email = entries[current_app.config['LDAPCLIENT_EMAIL_ATTRIBUTE']].values[0]
                login_form.email = email
            except LDAPKeyError:
                # Email is required - but leave form.email = None, and
                # pass a msg back to client via form.errors
                return

            try:
                full_name = entries[current_app.config['LDAPCLIENT_FULL_NAME_ATTRIBUTE']].values[0]
                login_form.full_name = full_name
            except LDAPKeyError:
                # Doesn't matter, not required
                pass

    except LDAPBindError:    
        login_form.bind = False
        return


    return

    

      
    
                
            
