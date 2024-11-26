# -*- coding: utf-8 -*-
"""Login form for ldap."""

from __future__ import absolute_import, print_function

from flask import request
from flask_security.forms import Form, NextFormMixin
from wtforms import PasswordField, StringField, SubmitField, validators

from .utils import (
    config_value as cv,
)

from .dit import form_validator


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
            """
            To do - this should not return before all validation steps have been taken.
            """
            if not super(LoginForm, self).validate(extra_validators=extra_validators):
                return False

            return form_validator(self)

    return LoginForm
