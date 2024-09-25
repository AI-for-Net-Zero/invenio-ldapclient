from flask import current_app
import ldap3
from ldap3 import Tls, Connection

def get_config(app):
    """ Lifted from flask-security
    """
    items = app.config.items()
    prefix = 'LDAPCLIENT_'

    def strip_prefix(tup):
        return (tup[0].replace(prefix, ''), tup[1])

    return dict([strip_prefix(i) for i in items if i[0].startswith(prefix)])

def config_value(key, app=None, default=None):
    """ Also lifted from flask-security.
    Get an invenio-ldapclient config value

    :param key: The configuration key without the prefix `LDAPCLIENT_`
    :param app: An optional specific application to inspect. Defaults to
                Flask's `current_app`
    :param default: An optional default value if the value is not set
    """
    app = app or current_app
    return get_config(app).get(key.upper(), default)

def _ldap_anon_connection():
    cv = config_value
    
    servers = current_app.extensions['invenio-ldapclient'].servers
    
    conn_kwargs = cv('connection_kwargs') if cv('connection_kwargs') else {}
    conn = Connection(servers, **conn_kwargs)

    return conn

def _search_DIT(connection, form):
    cv = config_value
    
    username = form.username.data
    
    search_base = cv('user_search_base')
    search_filter = cv('user_search_filter')
    search_kwargs = cv('user_search_kwargs') if cv('user_search_kwargs') else {}

    connection.search(search_base = search_base,
                      search_filter = search_filter(username),
                      attributes = ldap3.ALL_ATTRIBUTES,
                      **search_kwargs)
    
def _check_access_permitted(form, connection):
    cv = config_value
    
    search_base = cv('group_search_base')
    group_filters = cv('group_filters')

    if group_filters is None:
        form.access_permitted = False
        return
    
    group_member = ( connection.search(search_base, f(form.username.data) )
                     for f in group_filters )

    form.access_permitted = any(group_member)

    
                 
