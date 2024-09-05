from flask import current_app
from ldap3 import Tls

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
