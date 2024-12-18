import shutil
import tempfile

from flask import Flask
from flask_babelex import Babel
from invenio_accounts import InvenioAccountsREST
from invenio_accounts.views.rest import create_blueprint


instance_path = tempfile.mkdtemp(prefix="invenio_ldapclient")

app = Flask("testapp", instance_path=instance_path)
app.config.update(
    SECRET_KEY="SECRET_KEY",
    TESTING=True,
)


app.config.update(
    ACCOUNTS_REST_AUTH_VIEWS={
        "login": "invenio_ldapclient.views_rest:LoginView",
        "logout": "invenio_accounts.views.rest:LogoutView",
        "user_info": "invenio_accounts.views.rest:UserInfoView",
        "register": "invenio_accounts.views.rest:RegisterView",
        "forgot_password": "invenio_accounts.views.rest:ForgotPasswordView",
        "reset_password": "invenio_accounts.views.rest:ResetPasswordView",
        "change_password": "invenio_accounts.views.rest:ChangePasswordView",
        "send_confirmation": "invenio_accounts.views.rest:SendConfirmationEmailView",
        "confirm_email": "invenio_accounts.views.rest:ConfirmEmailView",
        "sessions_list": "invenio_accounts.views.rest:SessionsListView",
        "sessions_item": "invenio_accounts.views.rest:SessionsItemView",
    },
    SECURITY_CONFIRMABLE=False,
    SECURITY_REGISTERABLE=False,
    SECURITY_CHANGEABLE=False,
    SECURITY_RECOVERABLE=False,
    LDAPCLIENT_USERNAME_PLACEHOLDER="Username",
)

# Babel(app)
InvenioAccountsREST(app)
bp = create_blueprint(app)
app.register_blueprint(bp, url_prefix="/api")

client = app.test_client()

response = client.post("api/login")
assert b"hello" in response.get_data()

shutil.rmtree(instance_path)
