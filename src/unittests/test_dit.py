from unittest.mock import Mock, MagicMock, patch

from invenio_ldapclient import InvenioLDAPClientUI
from invenio_accounts import InvenioAccountsUI

from invenio_ldapclient.dit import (
    _ldap_anon_connection,
    check_dit_fetch_entries,
    _0_USERS_FOUND,
    _DUP_USERS_FOUND,
    _USERNAME_PASSWD,
)

import ldap3

RequestObject = type(
    "RequestObject",
    (),
    {
        "get_username": lambda: None,
        "get_password": lambda: None,
        "handle_no_users": lambda: None,
        "handle_dup_users": lambda: None,
        "handle_passwd_invalid": lambda: None,
        "handle_no_email": lambda: None,
        "set_email": lambda: None,
        "handle_access_not_permitted": lambda: None,
    },
)


def test_bind_fail():
    mock_request_object = Mock(spec_set=RequestObject())

    mock_request_object.get_username = Mock(return_value="spongebob01")
    mock_request_object.get_password = Mock(return_value="password123")
    mock__get_entry_and_try_rebind = Mock(return_value=(None, _0_USERS_FOUND))

    @patch(
        "invenio_ldapclient.dit._get_entry_and_try_rebind",
        mock__get_entry_and_try_rebind,
    )
    @patch("invenio_ldapclient.dit.hash_password")
    def test_no_users_found(mock_hash_password):
        ret = check_dit_fetch_entries(mock_request_object)

        mock_hash_password.assert_called_once()
        mock_hash_password.assert_called_with("password123")
        assert ret is False
        mock_request_object.handle_no_users.assert_called()
        mock_request_object.get_username.assert_called_once()
        mock_request_object.get_password.assert_called_once()
        assert not mock_request_object.handle_dup_users.called
        assert not mock_request_object.handle_passwd_invalid.called
        assert not mock_request_object.handle_no_email.called
        assert not mock_request_object.set_email.called
        assert not mock_request_object.handle_access_not_permitted.called

    test_no_users_found()

    mock_request_object.reset_mock()
    mock__get_entry_and_try_rebind.reset_mock(return_value=True)
    mock__get_entry_and_try_rebind.return_value = (None, _DUP_USERS_FOUND)

    @patch(
        "invenio_ldapclient.dit._get_entry_and_try_rebind",
        mock__get_entry_and_try_rebind,
    )
    @patch("invenio_ldapclient.dit.hash_password")
    def test_dup_found(mock_hash_password):
        ret = check_dit_fetch_entries(mock_request_object)

        mock_hash_password.assert_called_once()
        mock_hash_password.assert_called_with("password123")
        assert ret is False
        mock_request_object.handle_dup_users.assert_called()
        mock_request_object.get_username.assert_called_once()
        mock_request_object.get_password.assert_called_once()
        assert not mock_request_object.handle_no_users.called
        assert not mock_request_object.handle_passwd_invalid.called
        assert not mock_request_object.handle_no_email.called
        assert not mock_request_object.set_email.called
        assert not mock_request_object.handle_access_not_permitted.called

    test_dup_found()

    mock_request_object.reset_mock()
    mock__get_entry_and_try_rebind.reset_mock(return_value=True)
    mock__get_entry_and_try_rebind.return_value = (None, _USERNAME_PASSWD)

    @patch(
        "invenio_ldapclient.dit._get_entry_and_try_rebind",
        mock__get_entry_and_try_rebind,
    )
    @patch("invenio_ldapclient.dit.hash_password")
    def test_passwd_invalid(mock_hash_password):
        ret = check_dit_fetch_entries(mock_request_object)

        mock_hash_password.assert_called_once()
        mock_hash_password.assert_called_with("password123")
        assert ret is False
        mock_request_object.handle_passwd_invalid.assert_called()
        mock_request_object.get_username.assert_called_once()
        mock_request_object.get_password.assert_called_once()
        assert not mock_request_object.handle_no_users.called
        assert not mock_request_object.handle_dup_users.called
        assert not mock_request_object.handle_no_email.called
        assert not mock_request_object.set_email.called
        assert not mock_request_object.handle_access_not_permitted.called

    test_passwd_invalid()


def test_bind_succeed_no_email():
    mock_request_object = Mock(spec_set=RequestObject())

    mock_entry = MagicMock()
    mock_entry.__getattribute__ = Mock(side_effect=AttributeError)

    mock__get_entry_and_try_rebind = Mock(return_value=(mock_entry, None))

    mock_cv = Mock(return_value="mail")

    @patch(
        "invenio_ldapclient.dit._get_entry_and_try_rebind",
        mock__get_entry_and_try_rebind,
    )
    @patch("invenio_ldapclient.dit.cv", mock_cv)
    def test_no_email():
        ret = check_dit_fetch_entries(mock_request_object)
        assert ret == False

        mock_request_object.handle_no_email.assert_called()
        assert not mock_request_object.handle_passwd_invalid.called
        assert not mock_request_object.handle_no_users.called
        assert not mock_request_object.handle_dup_users.called
        assert not mock_request_object.set_email.called
        assert not mock_request_object.handle_access_not_permitted.called

    test_no_email()


def test_bind_succeed_has_email_no_access():
    mock_request_object = Mock(spec_set=RequestObject())
    mock_request_object.get_username = Mock(return_value="spongebob01")
    mock_request_object.get_password = Mock(return_value="password123")

    mock_entry = MagicMock()
    mock_entry.mail = ["spongebob@yahootmail.co.cz"]

    mock__get_entry_and_try_rebind = Mock(return_value=(mock_entry, None))

    mock_cv = Mock(return_value="mail")
    mock__is_access_permitted = Mock(return_value=False)

    @patch(
        "invenio_ldapclient.dit._get_entry_and_try_rebind",
        mock__get_entry_and_try_rebind,
    )
    @patch("invenio_ldapclient.dit.cv", mock_cv)
    @patch("invenio_ldapclient.dit._is_access_permitted", mock__is_access_permitted)
    def inner():
        ret = check_dit_fetch_entries(mock_request_object)
        assert ret == False

        assert not mock_request_object.handle_no_email.called
        assert not mock_request_object.handle_passwd_invalid.called
        assert not mock_request_object.handle_no_users.called
        assert not mock_request_object.handle_dup_users.called
        assert mock_request_object.set_email.called_with("spongebob@yahootmail.co.cz")
        assert mock_request_object.handle_access_not_permitted.called
        assert mock__is_access_permitted.called_with("spongebob01")

    inner()


def test_bind_succeed_has_email_has_access():
    mock_request_object = Mock(spec_set=RequestObject())
    mock_request_object.get_username = Mock(return_value="spongebob01")
    mock_request_object.get_password = Mock(return_value="password123")

    mock_entry = MagicMock()
    mock_entry.mail = ["spongebob@yahootmail.co.cz"]

    mock__get_entry_and_try_rebind = Mock(return_value=(mock_entry, None))

    mock_cv = Mock(return_value="mail")
    mock__is_access_permitted = Mock(return_value=True)

    @patch(
        "invenio_ldapclient.dit._get_entry_and_try_rebind",
        mock__get_entry_and_try_rebind,
    )
    @patch("invenio_ldapclient.dit.cv", mock_cv)
    @patch("invenio_ldapclient.dit._is_access_permitted", mock__is_access_permitted)
    def inner():
        ret = check_dit_fetch_entries(mock_request_object)
        assert ret == True

        assert not mock_request_object.handle_no_email.called
        assert not mock_request_object.handle_passwd_invalid.called
        assert not mock_request_object.handle_no_users.called
        assert not mock_request_object.handle_dup_users.called
        assert mock_request_object.set_email.called_with("spongebob@yahootmail.co.cz")
        assert not mock_request_object.handle_access_not_permitted.called
        assert mock__is_access_permitted.called_with("spongebob01")

    inner()
