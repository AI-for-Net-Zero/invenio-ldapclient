# -*- coding: utf-8 -*-
"""Login form for ldap."""

from __future__ import absolute_import, print_function

from flask_security.forms import Form
from wtforms import PasswordField, StringField, validators


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
