"""Invenio-LDAPClient login view."""

from __future__ import absolute_import, print_function

from flask import after_this_request
from flask import current_app
from flask import redirect, render_template
from flask_security import login_user
from flask_security.decorators import anonymous_user_required
from flask_security.utils import get_post_login_redirect


from .forms import login_form_factory, Form_Request_Obj
from .utils import config_value as cv
from .db import find_or_register_user, _commit
from .dit import check_dit_fetch_entries


@anonymous_user_required
def login_ldap_ui():
    form = login_form_factory(current_app)()

    form_request_object = Form_Request_Obj(form)

    if form.validate_on_submit():
        entry = check_dit_fetch_entries(form_request_object)
        if entry:
            user = find_or_register_user(form_request_object)
            login_user(user)
            after_this_request(_commit)  # Calls db.session.commit()
            return redirect(get_post_login_redirect(form.next.data))
        else:
            return render_template(cv("login_user_template"), login_user_form=form)
    else:
        return render_template(cv("login_user_template"), login_user_form=form)
