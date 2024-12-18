from invenio_accounts.views.rest import _abort, _commit, get_message

from .rest_request_object import Kwarg_Request_Obj
from .dit import check_dit_fetch_entries


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
        if "username" not in kwargs:
            _abort("Username required", "username")
        if "password" in kwargs:
            _abort("Password required", "password")

        request_obj = Kwarg_Request_Obj(kwargs)

        entry = check_dit_fetch_entries(request_obj)
        if "abort_msg" in request_obj:
            _abort(request_obj["abort_msg"],
                   field = request_obj["abort_field"])

        elif entry:
            user = find_or_register_user(request_obj)
            login_user(user)
            after_this_request(_commit)
            return self.success_response(None)
        
        else:
            raise RuntimeError("Fell through invenio_ldapclient.LoginView.post")
            
            
            

        # if username not in kwargs
        # if password not in kwargs
        # dit(kwargs) (adds "email" and "full_name" to kwargs
        #
        # if dit(kwargs):

        # dit.check_credentials(**kwargs)
        # 1. Replicate all steps in forms.validate_form_and_get_user
        # 2. Enable separate group check for REST access (load two configs, so no change reqd)
        # 3. User inv-acc's _abort and REST - figure out less painful way to test for v2-5
