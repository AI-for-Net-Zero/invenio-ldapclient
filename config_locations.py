import re
import invenio_ldapclient

def config_load(mod = invenio_ldapclient.config):
    keys = []
    
    for k in dir(mod):
        if k.startswith('LDAPCLIENT'):
            keys.append(k)

    return keys


