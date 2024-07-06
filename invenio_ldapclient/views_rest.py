from flask import current_app
from flask.views import MethodView

from .forms import login_form_factory
from .views import _ldap_connection

class LoginView(MethodView):
    def post(self, **kwargs):
        form = login_form_factory(current_app)()

        if form.validate_on_submit():
            connection = _ldap_connection(form)

        return 'hello'
            

