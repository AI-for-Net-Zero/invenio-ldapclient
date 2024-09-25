LDAP_SERVER_IP='10.0.3.159'
GROUP_FILTERS = [lambda u : f'(&(memberUid={u})(objectClass=posixGroup)(cn=green))',
                 lambda u : f'(&(memberUid={u})(objectClass=posixGroup)(cn=blue))']
USER_FILTER = lambda u : f'(&(uid={u})(objectClass=posixAccount))'

SECRET_KEY = 'secret'
WTF_CSRF_ENABLED = False
EXPLAIN_TEMPLATE_LOADING = True

LDAPCLIENT_SERVER_KWARGS = {'host': LDAP_SERVER_IP,
                            'port': 389,
                            'use_ssl': False
                            }                      

LDAPCLIENT_EXCLUSIVE_AUTHENTICATION = True
LDAPCLIENT_BIND_BASE = lambda u : f'uid={u},ou=People,ou=Local,dc=example,dc=com'
LDAPCLIENT_GROUP_SEARCH_BASE = 'dc=example,dc=com'
