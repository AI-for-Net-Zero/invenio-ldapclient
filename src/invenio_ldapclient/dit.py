from flask import current_app
import ldap3
from flask_security.utils import hash_password

from .utils import config_value as cv

_0_USERS_FOUND = "0_USERS_FOUND"
_DUP_USERS_FOUND = "DUP_USERS_FOUND"
_USERNAME_PASSWD = "USERNAME_PASSWD"


def _ldap_anon_connection():
    servers = current_app.extensions["invenio-ldapclient"].servers

    conn_kwargs = cv("connection_kwargs") if cv("connection_kwargs") else {}
    conn = ldap3.Connection(servers, **conn_kwargs)

    return conn


def _search_DIT(connection, username):
    search_base = cv("user_search_base")
    search_filter = cv("user_search_filter")
    search_kwargs = cv("user_search_kwargs") if cv("user_search_kwargs") else {}

    connection.search(
        search_base=search_base,
        search_filter=search_filter(username),
        attributes=ldap3.ALL_ATTRIBUTES,
        **search_kwargs,
    )


def _get_entry_and_try_rebind(username, password):
    entry = None

    with _ldap_anon_connection() as c:
        _search_DIT(c, username)

        if len(c.entries) == 0:
            return None, _0_USERS_FOUND

        elif len(c.entries) > 1:
            return None, _DUP_USERS_FOUND

        else:
            entry = c.entries[0]
            if entry and c.rebind(entry.entry_dn, password):
                return entry, None
            else:
                return None, _USERNAME_PASSWD


def _is_access_permitted(username):
    search_base = cv("group_search_base")
    group_filters = cv("group_search_filters")

    if group_filters is None:
        return False

    with _ldap_anon_connection() as c:
        group_member = (c.search(search_base, f(username)) for f in group_filters)

        return any(group_member)


"""  
def _check_user(username, password):
   
    #Search DIT for username
    #Check bind username and password
    #Check access permitted
    #Check email in directory
   
    ret = {
        "bind": None,
        "bind_fail_reason": None,
        "access_permitted": None,
        "email": None,
        "full_name": None}

    with _ldap_anon_connection() as c:
        _search_DIT(c, username)
        # entries = c.entries

        entry = None
        if len(c.entries) == 0:
            ret["bind"] = False
            ret["bind_fail_reason"] = _0_USERS_FOUND

        elif len(c.entries) > 1:
            ret["bind"] = False
            ret["bind_fail_reason"] = _DUP_USERS_FOUND

        else:
            entry = c.entries[0]
            if entry and c.rebind(entry.entry_dn, password):
                # User is authenticated
                ret["bind"] = True
            else:
                ret["bind"] = False
                ret["bind_fail_reason"] = _USERNAME_PASSWD

        ret["access_permitted"] = _check_access_permitted(username, c)

        if entry:
            try:
                email = entry[cv("email_attribute")].values
            except ldap3.core.exceptions.LDAPKeyError:
                # Email is required - but leave form.email = None, and
                # pass a msg back to client via form.errors
                pass
            else:
                ret["email"] = email

    return ret
"""


def form_validator(form):
    username = form.username.data
    password = form.password.data

    entry, bind_fail_reason = _get_entry_and_try_rebind(username, password)

    if not entry:
        hash_password(form.password.data)

        if bind_fail_reason in [_0_USERS_FOUND, _USERNAME_PASSWD]:
            form.username.errors.append("Username and password not valid")
            return False

        elif bind_fail_reason is _DUP_USERS_FOUND:
            form.username.errors.append(
                "Login failed (duplicate username).  Contact administrator."
            )
            return False

        else:
            return False

    try:
        email = entry[cv("email_attribute")].values
    except ldap3.core.exceptions.LDAPKeyError:
        # Email is required - but leave form.email = None, and
        # pass a msg back to client via form.errors
        form.username.errors.append("User email not registered.")
        return False
    else:
        form.email = email

    access_permitted = _is_access_permitted(username)

    if not access_permitted:
        form.username.errors.append(
            "Login failed (access permission).  Contact administrator."
        )
        return False

    return True
