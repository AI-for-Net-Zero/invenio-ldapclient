from flask import current_app


def get_config(app):
    """Lifted from flask-security"""
    items = app.config.items()
    prefix = "LDAPCLIENT_"

    def strip_prefix(tup):
        return (tup[0].replace(prefix, ""), tup[1])

    return dict([strip_prefix(i) for i in items if i[0].startswith(prefix)])


def config_value(key, app=None, default=None):
    """Also lifted from flask-security.
    Get an invenio-ldapclient config value

    :param key: The configuration key without the prefix `LDAPCLIENT_`
    :param app: An optional specific application to inspect. Defaults to
                Flask's `current_app`
    :param default: An optional default value if the value is not set
    """
    app = app or current_app
    return get_config(app).get(key.upper(), default)
