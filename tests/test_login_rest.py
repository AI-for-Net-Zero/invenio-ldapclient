from invenio_accounts import InvenioAccountsREST
from invenio_accounts.views.rest import create_blueprint

def test_login_rest_get_not_allowed(configured_app):
    
    client = configured_app.test_client()

    response = client.get('/api/login')
    assert response.status == '405 METHOD NOT ALLOWED'
    
