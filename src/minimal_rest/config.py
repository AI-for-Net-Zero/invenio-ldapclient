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


LDAPCLIENT_TEMPORARY_EMAIL_FIX = False
LDAPCLIENT_TEMPORARY_EMAIL_FIX_DOMAIN = "ic.ac.uk"

LDAPCLIENT_MSG_NO_USERS = "Woah! No users were found"
LDAPCLIENT_MSG_DUP_USERS = "WOAH! Username matches multiple DIT entries"
LDAPCLIENT_MSG_PASSWD = "Gah... Username & password invalid"
LDAPCLIENT_MSG_NO_EMAIL = "Hmmm... DIT entry has no email address"
LDAPCLIENT_MSG_NO_ACCESS = "Halt!  You do not have access"
