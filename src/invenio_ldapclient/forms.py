# -*- coding: utf-8 -*-
"""Login form for ldap."""

from __future__ import absolute_import, print_function

from flask import Markup, request, current_app
from flask_security.forms import Form, NextFormMixin
from flask_security.utils import url_for_security, hash_password
from wtforms import PasswordField, StringField, SubmitField, validators

from .utils import _ldap_anon_connection, _search_DIT, _check_access_permitted, config_value as cv


from ldap3.core.exceptions import LDAPBindError, LDAPKeyError

_0_USERS_FOUND = '0_USERS_FOUND'
_DUP_USERS_FOUND = 'DUP_USERS_FOUND'
_USERNAME_PASSWD = 'USERNAME_PASSWD'


def login_form_factory(app):
    """Inserts e.g., current_app, into local namespace of form class"""
    class LoginForm(Form, NextFormMixin):
        """LDAP login form."""

        username = StringField(
            cv('username_placeholder', app),
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

        def validate(self, extra_validators=None):
            '''
            To do - this should not return before all validation steps have been taken.
            '''
            if not super(LoginForm, self).validate(extra_validators=extra_validators):
                return False

            validate_form_and_get_user(self)
            
            if not self.bind:
                hash_password(self.password.data)

                if self.bind_fail_reason == _DUP_USERS_FOUND:
                    self.username.errors.append('Login failed (duplicate username).  Contact administrator.')
                    #LOG something
                else:
                    self.username.errors.append('Username and password not valid')

                return False

            elif not self.access_permitted:
                self.username.errors.append('Login failed (access permission).  Contact administrator.')
                return False

            elif not self.email:
                self.username.errors.append('User email not registered.')
                return False
            
            else:
                return True

    return LoginForm


def validate_form_and_get_user(form):
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
    
    To do - this should not return before all validation steps have been taken.  Check exception 
    handling
    """
    form.bind = None
    form.bind_fail_reason = None
    form.access_permitted = None
    form.email = None
    form.full_name = None
    
    with _ldap_anon_connection() as c:
        _search_DIT(c, form)
        #entries = c.entries
        
        if len(c.entries) == 0:
            form.bind = False
            form.bind_fail_reason = _0_USERS_FOUND
            return
            
        elif len(c.entries) > 1:
            form.bind = False
            form.bind_fail_reason = _DUP_USERS_FOUND
            return
            
        else:
            entry = c.entries[0]

        if c.rebind(entry.entry_dn, form.password.data):
            # User is authenticated
            form.bind = True
        else:
            form.bind = False
            form.bind_fail_reason = _USERNAME_PASSWD
            return
            
        _check_access_permitted(form, c)

        try:
            email = entry[cv('email_attribute')].values
        except LDAPKeyError:
            # Email is required - but leave form.email = None, and
            # pass a msg back to client via form.errors
            pass
        else:
            form.email = email
                
    return

    

      
    
                
            
