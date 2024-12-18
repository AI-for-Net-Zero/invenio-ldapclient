from invenio_ldapclient import InvenioLDAPClientUI
from ldap3 import MOCK_SYNC

import pytest


def test_raise_not_implemented(app):
    group_filters = [
        lambda u: f"(&(memberUid={u})(objectClass=posixGroup)(cn=green))",
        lambda u: f"(&(memberUid={u})(objectClass=posixGroup)(cn=blue))",
    ]

    def user_filter(uid):
        return f"(&(uid={uid})(objectClass=posixAccount))"

    def bind_base(uid):
        return f"uid={uid},ou=People,ou=Local,o=Example,dc=example,dc=com"

    app.config.update(
        WTF_CSRF_ENABLED=False,
        LDAPCLIENT_EXCLUSIVE_AUTHENTICATION=False,
        LDAPCLIENT_SERVER_KWARGS={
            "host": "ldap.0.example.com",
            "port": 389,
            "use_ssl": False,
            "tls": None,
        },
        LDAPCLIENT_FULL_NAME_ATTRIBUTE="displayName",
        LDAPCLIENT_BIND_BASE=bind_base,
        LDAPCLIENT_USER_SEARCH_BASE="ou=People,ou=Local,o=Example,dc=example,dc=com",
        LDAPCLIENT_USER_SEARCH_FILTER=user_filter,
        LDAPCLIENT_CONNECTION_KWARGS={"client_strategy": MOCK_SYNC},
        LDAPCLIENT_GROUP_SEARCH_BASE="ou=Groups,ou=Local,o=Example,dc=example,dc=com",
        LDAPCLIENT_GROUP_FILTERS=group_filters,
    )

    with pytest.raises(NotImplementedError):
        InvenioLDAPClientUI(app)
