# -*- coding: utf-8 -*-
"""Login form for ldap."""

from __future__ import absolute_import, print_function

from flask import request
from flask_security.forms import Form, NextFormMixin
from wtforms import PasswordField, StringField, SubmitField, validators

from .utils import (
    config_value as cv,
)


def login_form_factory(app):
    """Inserts e.g., current_app, into local namespace of form class"""

    class LoginForm(Form, NextFormMixin):
        """LDAP login form."""

        username = StringField(
            cv("username_placeholder", app), validators=[validators.InputRequired()]
        )
        password = PasswordField("Password", validators=[validators.InputRequired()])
        submit = SubmitField("Login")

        def __init__(self, *args, **kwargs):
            super(LoginForm, self).__init__(*args, **kwargs)
            if not self.next.data:
                self.next.data = request.args.get("next", "")

        def validate(self, extra_validators=None):
            return super(LoginForm, self).validate(extra_validators=extra_validators)

    return LoginForm


class Form_Request_Obj(object):
    def __init__(self, login_form):
        self.login_form = login_form

    def get_username(self):
        return self.login_form.username.data

    def get_password(self):
        return self.login_form.password.data

    def get_email(self):
        if hasattr(self, "email"):
            return self.email
        else:
            return None

    def set_email(self, email):
        self.email = email

    def handle_no_users(self):
        self.login_form.username.errors.append("Username and password not valid")

    def handle_dup_users(self):
        self.login_form.username.errors.append(
            "Login failed (duplicate username).  Contact administrator."
        )

    def handle_passwd_invalid(self):
        self.login_form.username.errors.append("Username and password not valid")

    def handle_no_email(self):
        self.login_form.username.errors.append("User email not registered.")

    def handle_access_not_permitted(self):
        self.login_form.username.errors.append(
            "Login failed (access permission).  Contact administrator."
        )
