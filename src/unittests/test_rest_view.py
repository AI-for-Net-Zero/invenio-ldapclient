import pytest

@pytest.mark.skip()
def test_class():
    from invenio_ldapclient.views import LoginView

    LoginView()
