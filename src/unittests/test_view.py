from unittest.mock import Mock, patch


def test_login_ldap_ui_form_not_valid():

    mock_form = Mock(validate_on_submit=lambda: False)
    mock_LoginForm = Mock(return_value=mock_form)
    mock_login_form_factory = Mock(return_value=mock_LoginForm)
    mock_current_user = Mock(is_authenticated=False)

    @patch("flask_security.decorators.current_user", mock_current_user)
    @patch("invenio_ldapclient.views.cv", Mock(return_value="some_template.html"))
    @patch("invenio_ldapclient.views.render_template")
    @patch("invenio_ldapclient.views.login_form_factory", mock_login_form_factory)
    def inner(mock_render_template):
        from invenio_ldapclient.views import login_ldap_ui

        login_ldap_ui()
        mock_render_template.assert_called_with(
            "some_template.html", login_user_form=mock_form
        )

    inner()


def test_login_ldap_ui_form_valid_no_entry():

    mock_form = Mock(validate_on_submit=lambda: True)
    mock_LoginForm = Mock(return_value=mock_form)
    mock_login_form_factory = Mock(return_value=mock_LoginForm)
    mock_current_user = Mock(is_authenticated=False)
    mock_check_dit_fetch_entries = Mock(return_value=False)

    @patch("flask_security.decorators.current_user", mock_current_user)
    @patch("invenio_ldapclient.views.cv", Mock(return_value="some_template.html"))
    @patch("invenio_ldapclient.views.render_template")
    @patch("invenio_ldapclient.views.login_form_factory", mock_login_form_factory)
    @patch(
        "invenio_ldapclient.views.check_dit_fetch_entries", mock_check_dit_fetch_entries
    )
    def inner(mock_render_template):
        from invenio_ldapclient.views import login_ldap_ui

        login_ldap_ui()
        mock_render_template.assert_called_with(
            "some_template.html", login_user_form=mock_form
        )

    inner()


def test_login_ldap_ui_all_good():

    mock_form = Mock(validate_on_submit=lambda: True)
    mock_form.next.data = "http://where-to-next.com"
    mock_LoginForm = Mock(return_value=mock_form)
    mock_login_form_factory = Mock(return_value=mock_LoginForm)
    mock_current_user = Mock(is_authenticated=False)
    mock_check_dit_fetch_entries = Mock(return_value=True)
    mock_form_request_obj = Mock()
    mock_Form_Request_Obj = Mock(return_value=mock_form_request_obj)

    mock_user = Mock()

    @patch("invenio_ldapclient.views.Form_Request_Obj", mock_Form_Request_Obj)
    @patch("flask_security.decorators.current_user", mock_current_user)
    @patch("invenio_ldapclient.views.login_form_factory", mock_login_form_factory)
    @patch(
        "invenio_ldapclient.views.check_dit_fetch_entries", mock_check_dit_fetch_entries
    )
    @patch("invenio_ldapclient.views.find_or_register_user", return_value=mock_user)
    @patch("invenio_ldapclient.views.login_user")
    @patch("invenio_ldapclient.views.after_this_request")
    @patch(
        "invenio_ldapclient.views.get_post_login_redirect",
        return_value="<h1>You have been redirected!</h1>",
    )
    @patch("invenio_ldapclient.views.redirect")
    def inner(
        mock_redirect,
        mock_get_post_login_redirect,
        mock_after_this_request,
        mock_login_user,
        mock_find_or_register_user,
    ):

        from invenio_ldapclient.views import login_ldap_ui, _commit
        from invenio_ldapclient.forms import Form_Request_Obj

        login_ldap_ui()

        mock_find_or_register_user.assert_called_with(mock_form_request_obj)
        mock_login_user.assert_called_with(mock_user)
        mock_after_this_request.assert_called_with(_commit)
        mock_get_post_login_redirect.assert_called_with("http://where-to-next.com")
        mock_redirect.assert_called_with("<h1>You have been redirected!</h1>")

    inner()
