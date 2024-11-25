import os

from flask import Flask
from invenio_i18n import InvenioI18N
from invenio_ldapclient import InvenioLDAPClientUI
from invenio_accounts import InvenioAccountsUI
#from invenio_accounts.views import blueprint
from invenio_assets import InvenioAssets
from invenio_db import InvenioDB
from flask_login import login_required
from flask_security.views import logout_user as logout_user

from ldap3 import ALL_ATTRIBUTES

ROOT_PAGE = """
<!DOCTYPE html>
<html>
<body>
<h1 style='color:blue'>Home page</h1>

</body>
</html>
"""

WELCOME_PAGE = """
<!DOCTYPE html>
<html>
<body>
<h1 style='color:blue'>Welcome!</h1>

<input type="button" onclick="location.href='/logout';" value="Log out" />
</body>
</html>
"""


LOGOUT_PAGE = """
<!DOCTYPE html>
<html>
<body>
<h1 style='color:blue'>Goodbye!</h1>
<p>Come back soon</p>
<input type="button" onclick="location.href='/login';" value="Log back in" />
</body>
</html>
"""

def create_app():
    INSTANCE_PATH = os.environ.get('INSTANCE_PATH')
    
    search_filter = lambda username : f'(&(uid={username})(objectClass=posixAccount))'
    group_filters = [lambda username : f'(&(memberUid={username})(cn=cats)(objectClass=posixGroup))',
                     lambda username : f'(&(memberUid={username})(cn=dogs)(objectClass=posixGroup))']

    app = Flask('minimal',
                instance_path=INSTANCE_PATH)

    try:
        os.makedirs(app.instance_path)
    except FileExistsError:
        pass
        
    db_uri = 'sqlite:///' + os.path.join(app.instance_path, 'minimal.db')

    app.config.from_pyfile('config.py')

    InvenioI18N(app)
    InvenioDB(app)
    InvenioLDAPClientUI(app)
    InvenioAccountsUI(app)

    @app.route('/')
    @login_required
    def root():
        return ROOT_PAGE
    
    @app.route('/welcome')
    @login_required
    def welcome():
        return WELCOME_PAGE

    @app.route('/logout')
    def logout():
        logout_user()
        return LOGOUT_PAGE

    return app



    '''
    app.config.update(SECRET_KEY = 'secret',
                      WTF_CSRF_ENABLED = False,
                      ACCOUNTS_BASE_TEMPLATE = 'invenio_accounts/base.html',
                      LDAPCLIENT_BASE_TEMPLATE = 'invenio_accounts/base_cover.html',
                      LDAPCLIENT_EXCLUSIVE_AUTHENTICATION = True,
                      EXPLAIN_TEMPLATE_LOADING = True,
                      
                      LDAPCLIENT_SERVERS = [{'host': '10.0.3.115',
                                            'port': 389,
                                            'use_ssl': None}],
                      

                      LDAPCLIENT_SEARCH = {'bind_base': 'ou=People,dc=example,dc=com',
                                           'search_base': 'dc=example,dc=com',
                                           'search_filter': search_filter,
                                           'group_filters': group_filters,
                                           'username_attribute': 'uid',
                                           'email_attribute': 'mail',
                                           'fullname_attribute': 'displayName',
                                           'search_attributes': ALL_ATTRIBUTES},
                      
                      LDAPCLIENT_USERNAME_PLACEHOLDER = 'User name',
                      LDAPCLIENT_AUTO_REGISTRATION = True,
                      #SECURITY_POST_LOGOUT_VIEW = 'invenio_ldapclient.ldap_login'
                      SQLALCHEMY_DATABASE_URI = db_uri
                    )
    '''
