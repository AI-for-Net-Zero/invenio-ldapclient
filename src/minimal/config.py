GROUP_FILTERS = [
    lambda u: f"(&(memberUid={u})(objectClass=posixGroup)(cn=green))",
    lambda u: f"(&(memberUid={u})(objectClass=posixGroup)(cn=blue))",
]
USER_FILTER = lambda u: f"(&(uid={u})(objectClass=shadowAccount))"
SECRET_KEY = "secret"
EXPLAIN_TEMPLATE_LOADING = True


LDAPCLIENT_SERVER_KWARGS = {"host": "ldap://mock-ldap", "use_ssl": False}

LDAPCLIENT_EXCLUSIVE_AUTHENTICATION = True
LDAPCLIENT_USER_SEARCH_BASE = "dc=example,dc=com"
LDAPCLIENT_USER_SEARCH_FILTER = lambda u: f"(&(uid={u})(objectclass=shadowAccount))"
LDAPCLIENT_GROUP_SEARCH_BASE = "dc=example,dc=com"
LDAPCLIENT_GROUP_SEARCH_FILTERS = [
    lambda u: f"(&(objectclass=posixGroup)(|(cn=green)(cn=blue))(memberUid={u}))"
]
