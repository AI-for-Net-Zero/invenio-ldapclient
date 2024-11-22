"""Invenio-LDAPClient login view."""

from __future__ import absolute_import, print_function

import uuid

from flask import Blueprint, after_this_request
from flask import current_app
from flask import flash, redirect, render_template, request
from flask_security import login_user
from flask_security.decorators import anonymous_user_required
from flask_security.utils import get_post_login_redirect

from ldap3 import ALL, ALL_ATTRIBUTES, Connection, Server, Tls, ServerPool, ROUND_ROBIN


from sqlalchemy import select
from invenio_ldapclient.forms import login_form_factory
from invenio_ldapclient.utils import config_value as cv
from invenio_ldapclient.db import find_or_register_user, add_user, update_user, _commit

'''
def create_blueprint(app):
    blueprint = Blueprint(
        'invenio_ldapclient',
        __name__,
        template_folder='templates',
        static_folder='static',
    )

    blueprint.route('/ldap-login', methods=['GET', 'POST'])(login_via_ldap)

    return blueprint
'''

@anonymous_user_required
def login_ldap_ui():
    form = login_form_factory(current_app)()

    if form.validate_on_submit():
        user = find_or_register_user(form)
        login_user(user)
        after_this_request(_commit) #Calls db.session.commit()
        return redirect(get_post_login_redirect(form.next.data))

    else:
        return render_template(
            cv('login_user_template'),
            login_user_form=form
        )    
