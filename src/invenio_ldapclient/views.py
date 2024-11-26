"""Invenio-LDAPClient login view."""

from __future__ import absolute_import, print_function

from flask import after_this_request
from flask import current_app
from flask import redirect, render_template
from flask_security import login_user
from flask_security.decorators import anonymous_user_required
from flask_security.utils import get_post_login_redirect

from webargs import fields
from invenio_accounts.views.rest import LoginView as _LoginView, use_kwargs

from invenio_ldapclient.forms import login_form_factory


from invenio_ldapclient.utils import config_value as cv
from invenio_ldapclient.db import find_or_register_user, _commit

"""
def create_blueprint(app):
    blueprint = Blueprint(
        'invenio_ldapclient',
        __name__,
        template_folder='templates',
        static_folder='static',
    )

    blueprint.route('/ldap-login', methods=['GET', 'POST'])(login_via_ldap)

    return blueprint
"""


@anonymous_user_required
def login_ldap_ui():
    form = login_form_factory(current_app)()

    if form.validate_on_submit():
        user = find_or_register_user(form)
        login_user(user)
        after_this_request(_commit)  # Calls db.session.commit()
        return redirect(get_post_login_redirect(form.next.data))

    else:
        return render_template(cv("login_user_template"), login_user_form=form)


class LoginView(_LoginView):
    post_args = {
        "username": fields.String(required=True),
        "password": fields.String(required=True),
    }

    def verify_login(self, user, password=None, **kwargs):
        pass

    @use_kwargs(post_args)
    def post(self, **kwargs):
        # 1. Replicate all steps in forms.validate_form_and_get_user
        # 2. Enable separate group check for REST access (load two configs, so no change reqd)
        # 3. User inv-acc's _abort and REST - figure out less painful way to test for v2-5
        return self.success_response(None)
