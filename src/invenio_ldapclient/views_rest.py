from invenio_accounts.views.rest import (_abort,
                                         _commit,
                                         get_message,
                                         fields,
                                         use_kwargs,
                                         LoginView as _LoginView)

from flask_security import login_user
from flask import after_this_request

from .rest_request_object import Kwarg_Request_Obj
from .dit import check_dit_fetch_entries
from .db import find_or_register_user


class LoginView(_LoginView):
    post_args = {
        "username": fields.String(required=True),
        "password": fields.String(required=True),
    } # Hide _LoginView.post_args

    def verify_login(self, user, password=None, **kwargs):
        raise RuntimeError("invenio_ldapclient.LoginView.verify_login")

    def get_user(*args, **kwargs):
        raise RuntimeError("invenio_ldapclient.LoginView.get_user")
                
    @use_kwargs(post_args)
    def post(self, **kwargs):
        request_obj = Kwarg_Request_Obj(kwargs)

        entry = check_dit_fetch_entries(request_obj)
        if "abort_msg" in request_obj.kwargs:
            _abort(request_obj.kwargs["abort_msg"],
                   field = request_obj.kwargs["abort_field"])

        elif entry:
            user = find_or_register_user(request_obj)
            login_user(user)
            after_this_request(_commit)
            return self.success_response(user)
        
        else:
            raise RuntimeError("Fell through invenio_ldapclient.LoginView.post")
