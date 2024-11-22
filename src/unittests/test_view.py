from unittest.mock import Mock, MagicMock, patch

anon_user_patch = patch('flask_security.decorators.anonymous_user_required', lambda f : f)
anon_user_patch.start()

from invenio_accounts import InvenioAccountsUI

from invenio_ldapclient import InvenioLDAPClientUI
from invenio_db import InvenioDB

from invenio_ldapclient.views import login_via_ldap


def test_login_existing_user_found_by_username(configured_app,
                                               mock_server_factory,
                                               mock_login_form_factory_factory,
                                               mock_user_factory):
    app = configured_app
    server = mock_server_factory('ldap.mock') # a mock ldap3.Server instance
    mockServer = Mock(return_value = server) # mocks ldap3.Server class

    mock_login_form_factory = mock_login_form_factory_factory()

    mock_user = mock_user_factory(full_name=None, affiliations=None)

    def _filter_by(username):
        return Mock(one_or_none = lambda : mock_user)
    
    mockUser = Mock(query = Mock(filter_by = _filter_by))
    
    InvenioDB(app)
    InvenioLDAPClientUI(app)
    InvenioAccountsUI(app)


    @patch('invenio_ldapclient.ext.Server', mockServer)
    @patch('invenio_ldapclient.views.login_form_factory', mock_login_form_factory)
    @patch('invenio_ldapclient.db.User', mockUser)
    @patch('invenio_ldapclient.views.login_user', Mock(return_value = True))
    @patch('invenio_ldapclient.db.db')
    def inner(mock_db):
        with app.test_request_context():
            response = login_via_ldap()
            assert mock_user.username == 'spongebob'
            assert mock_user.email == 'spongebob@example.com'
            assert mock_user.user_profile['full_name'] == 'Sponge Bob'
            assert mock_db.session_add.called_with(mock_user)
            assert response.status == '302 FOUND'
            assert b'<a href="/bikini/bottom/">/bikini/bottom/</a>. If not, click the link.\n' \
                in response.get_data()

            
    inner()

    



            
        
