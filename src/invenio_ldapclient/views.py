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

from .forms import login_form_factory, Form_Request_Obj
from .utils import config_value as cv
from .db import find_or_register_user, _commit
from .dit import check_dit_fetch_entries


@anonymous_user_required
def login_ldap_ui():
    form = login_form_factory(current_app)()

    if form.validate_on_submit():
        
        entry = check_dit_fetch_entries(Form_Request_Obj(form))
        user = find_or_register_user(Form_Request_Obj(form))

        login_user(user)
        after_this_request(_commit)  # Calls db.session.commit()
        return redirect(get_post_login_redirect(form.next.data))

    else:
        return render_template(cv("login_user_template"), login_user_form = form)

'''
class LoginView(_LoginView):
    post_args = {
        "username": fields.String(required=True),
        "password": fields.String(required=True),
    }

    def verify_login(self, user, password=None, **kwargs):
        pass

    def get_user(*args, **kwargs):
        """
        Hide invenio_accounts.views.rest.UserViewMixin.get_user
        """

    @use_kwargs(post_args)
    def post(self, **kwargs):
        # if username not in kwargs
        # if password not in kwargs
        # dit(kwargs) (adds "email" and "full_name" to kwargs
        # 
        # if dit(kwargs): 
        
        # dit.check_credentials(**kwargs)
        # 1. Replicate all steps in forms.validate_form_and_get_user
        # 2. Enable separate group check for REST access (load two configs, so no change reqd)
        # 3. User inv-acc's _abort and REST - figure out less painful way to test for v2-5
        return self.success_response(None)
'''
