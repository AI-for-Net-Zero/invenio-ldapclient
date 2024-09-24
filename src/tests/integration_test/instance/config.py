LDAP_SERVER_IP='10.0.3.159'
SECRET_KEY = 'secret'
WTF_CSRF_ENABLED = False
EXPLAIN_TEMPLATE_LOADING = True
LDAPCLIENT_SERVER_KWARGS = {'host': LDAP_SERVER_IP,
                            'port': 389,
                            'use_ssl': False
                            }                      
