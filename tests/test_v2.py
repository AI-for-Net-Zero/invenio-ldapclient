import pytest
import invenio_ldapclient
from unittest.mock import Mock, patch
from ldap3 import ALL, Tls
import ssl

def test_ldap_client_server_objects(app):
    _servers = [{'hostname': 'example1.com',
                 'port': 389,
                 'use_ssl': False},
                {'hostname': 'example2.com',
                 'port': 636,
                 'use_ssl': True,
                 'tls': {
                     'validate': ssl.CERT_NONE,
                     'version': ssl.PROTOCOL_TLSv1}
                 }]
    
    app.config.update(LDAPCLIENT_AUTHENTICATION = True,
                      LDAPCLIENT_SERVER_INFO = _servers)


    @patch('invenio_ldapclient.views.Server')
    @patch('invenio_ldapclient.views.Tls')
    def patched_test(mocked_tls, mocked_server):
        _server_gen = invenio_ldapclient.views._ldap_client_server_objects()
        next(_server_gen)
        mocked_server.assert_called_with('example1.com', port=389, use_ssl=False, get_info=ALL)
        mocked_tls.assert_not_called()
        
        next(_server_gen)
        mocked_server.assert_called_with('example2.com', port=636, use_ssl=True, get_info=ALL,
                                         tls = mocked_tls(validate = ssl.CERT_NONE,
                                                          version = ssl.PROTOCOL_TLSv1))
        
    patched_test()

def test_ldap_connection_no_username_or_password(app):
    _servers = [{'hostname': 'example1.com',
                 'port': 389,
                 'use_ssl': False},]

    app.config.update(LDAPCLIENT_AUTHENTICATION = True,
                      LDAPCLIENT_SERVER_INFO = _servers,
                      LDAPCLIENT_USERNAME_PLACEHOLDER = 'User name')

    from invenio_ldapclient.forms import login_form_factory

    with app.app_context():
        form = login_form_factory(app)()

        form.username = 'bob'

        conn = invenio_ldapclient.views._ldap_connection(form)
        assert conn is None

    
                
