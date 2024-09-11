from flask import current_app
from ldap3 import Tls, Connection, ALL_ATTRIBUTES

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


def _tls_dict_to_object(kwargs):
    '''
    Allow specifying a custom Tls object directly through config
    as well as params to construct ldap3.Tls
    '''
    obj = kwargs.get('tls', None)
    if obj and isinstance(obj, dict):
        kwargs_copy = kwargs.copy()
    
        tls_params = kwargs_copy.pop('tls', None)
        tls = Tls(**tls_params) if tls_params else None
    
        kwargs_copy['tls'] = tls
    
        return kwargs_copy
    else:
        return kwargs

def ldap_connection(form):
    """Make LDAP connection based on configuration."""
    form_pass = form.password.data
    form_user = form.username.data
    
    # <---------
    # LB: use plug-ins? - commenting out for now
    #
    #if app.config['LDAPCLIENT_CUSTOM_CONNECTION']:
    #    return app.config['LDAPCLIENT_CUSTOM_CONNECTION'](
    #        form_user, form_pass
    #    )
    # --------->
    ldap_user = "{}={},{}".format(
        current_app.config['LDAPCLIENT_USERNAME_ATTRIBUTE'],
        form_user,
        current_app.config['LDAPCLIENT_BIND_BASE']
    )

    servers = current_app.extensions['invenio-ldapclient'].servers
    conn = Connection(servers, ldap_user, form_pass, **current_app.config['LDAPCLIENT_CONN_KWARGS'])

    return conn

def check_group_memberships(form, connection):
    search_base = current_app.config['LDAPCLIENT_SEARCH_BASE']
    group_filters = current_app.config['LDAPCLIENT_GROUP_FILTERS']

    group_member = ( connection.search(search_base, f(form.username.data), attributes=ALL_ATTRIBUTES)
                     for f in group_filters )


    form.group = any(group_member)
    

def ldap_search(connection, username):
    """Fetch the user entry from LDAP."""
    search_attribs = current_app.config['LDAPCLIENT_SEARCH_ATTRIBUTES']
    if search_attribs is None:
        search_attribs = ALL_ATTRIBUTES

    connection.search(
        current_app.config['LDAPCLIENT_SEARCH_BASE'],
        '({}={})'.format(
            current_app.config['LDAPCLIENT_USERNAME_ATTRIBUTE'], username
        ),
        attributes=search_attribs)
    
def get_user(form):
    pass
