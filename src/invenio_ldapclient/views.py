"""Invenio-LDAPClient login view."""

from __future__ import absolute_import, print_function

import uuid

from flask import Blueprint, after_this_request
#from flask import current_app as app
from flask import current_app
from flask import flash, redirect, render_template, request
from flask_security import login_user
from invenio_accounts.models import User
from invenio_db import db
#from invenio_userprofiles.models import UserProfile
from ldap3 import ALL, ALL_ATTRIBUTES, Connection, Server, Tls, ServerPool, ROUND_ROBIN
from werkzeug.local import LocalProxy

from sqlalchemy import select
from .django import url_has_allowed_host_and_scheme
from .forms import login_form_factory


_security = LocalProxy(lambda: current_app.extensions['security'])
_datastore = LocalProxy(lambda: _security.datastore)

blueprint = Blueprint(
    'invenio_ldapclient',
    __name__,
    template_folder='templates',
    static_folder='static',
)

def _commit(response=None):
    _datastore.commit()
    return response

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

def _ldap_connection(form):#, app = current_app):
    """Make LDAP connection based on configuration."""
    if not form.validate_on_submit():
        return False

    form_pass = form.password.data
    form_user = form.username.data
    if not form_user or not form_pass:
        return False

    # <---------
    # LB: use plug-ins? - commenting out for now
    #
    #if app.config['LDAPCLIENT_CUSTOM_CONNECTION']:
    #    return app.config['LDAPCLIENT_CUSTOM_CONNECTION'](
    #        form_user, form_pass
    #    )
    # --------->

    servers = [ Server(**_tls_dict_to_object(kwargs)) for kwargs in current_app.config['LDAPCLIENT_SERVERS'] ]
    server_pool = ServerPool(servers, ROUND_ROBIN, active=True, exhaust=True)

    ldap_user = "{}={},{}".format(
        current_app.config['LDAPCLIENT_SEARCH']['username_attribute'],
        form_user,
        current_app.config['LDAPCLIENT_SEARCH']['bind_base']
    )

    conn = Connection(server_pool, ldap_user, form_pass)
    
    if not ( conn and conn.bind() ):
        return None

    search_base = current_app.config['LDAPCLIENT_SEARCH']['search_base']
    group_filters = current_app.config['LDAPCLIENT_SEARCH']['group_filters']

    group_member = ( conn.search(search_base, f(form_user), attributes=ALL_ATTRIBUTES)
                     for f in group_filters )

    if any(group_member):
        return conn

    else:
        conn.unbind()
        return None
        

def _search_ldap(connection, username):
    """Fetch the user entry from LDAP."""
    search_attribs = current_app.config['LDAPCLIENT_SEARCH']['search_attributes']
    if search_attribs is None:
        search_attribs = ALL_ATTRIBUTES

    connection.search(
        current_app.config['LDAPCLIENT_SEARCH']['search_base'],
        '({}={})'.format(
            current_app.config['LDAPCLIENT_SEARCH']['username_attribute'], username
        ),
        attributes=search_attribs)


def _register_or_update_user(entries, user_account=None):
    """Register or update a user."""
    email = entries[current_app.config['LDAPCLIENT_SEARCH']['email_attribute']].values[0]
    username = entries[current_app.config['LDAPCLIENT_SEARCH']['username_attribute']].values[0]
    if 'fullname_attribute' in current_app.config['LDAPCLIENT_SEARCH']:
        full_name = entries[current_app.config[
            'LDAPCLIENT_SEARCH']['fullname_attribute'
        ]].values[0]

    if user_account is None:
        kwargs = dict(email=email, active=True, password=uuid.uuid4().hex)
        _datastore.create_user(**kwargs)
        user_account = User.query.filter_by(email=email).one_or_none()

        user_account.username = username
        if 'fullname_attribute' in current_app.config['LDAPCLIENT_SEARCH']:
            user_account.user_profile = {'full_name': full_name}
            
        db.session.add(user_account)
        return user_account
    else:
        user_account.username = username
        if 'fullname_attribute' in current_app.config['LDAPCLIENT_SEARCH']:
            user_account.user_profile = {'full_name': full_name}
        
        user_account.email = email
        db.session.add(user_account)
        return user_account

    #profile.full_name = full_name
    #user_account.username = username
    #db.session.add(user_account)
    #return user_account


def _find_or_register_user(connection, username):
    """Find user by email, username or register a new one."""
    _search_ldap(connection, username)

    entries = connection.entries[0]
    if not entries:
        return None

    try:
        email = entries[current_app.config['LDAPCLIENT_SEARCH']['email_attribute']].values[0]
    except IndexError:
        # Email is required
        return None

    # Try by username first
    #user = User.query.join(UserProfile).filter(
    #    UserProfile.username == username
    #).one_or_none()
    user = User.query.filter_by(username=username).one_or_none()

    # Try by email next
    if not user and current_app.config['LDAPCLIENT_FIND_BY_EMAIL']:
        user = User.query.filter_by(email=email).one_or_none()

    if user:
        if not user.active:
            return None
        return _register_or_update_user(entries, user_account=user)

    # Register new user
    if current_app.config['LDAPCLIENT_AUTO_REGISTRATION']:
        return _register_or_update_user(entries)


@blueprint.route('/ldap-login', methods=['GET', 'POST'])
def ldap_login():
    """
    LDAP login form view.

    Process login request using LDAP and register
    the user if needed.
    """
    form = login_form_factory(current_app)()

    if form.validate_on_submit():

        connection = _ldap_connection(form)

        if connection and connection.bind():
            after_this_request(_commit)
            user = _find_or_register_user(connection, form.username.data)

            if user and login_user(user, remember=False):
                next_page = request.args.get('next')

                # Only allow relative URL for security
                #if not next_page or next_page.startswith('http'):
                if not url_has_allowed_host_and_scheme(next_page,
                                                       allowed_hosts = None,
                                                       require_https = \
                                                       current_app.config['LDAPCLIENT_REQUIRE_HTTPS']):
                #if not next_page or next_page.startswith('http'): 
                    next_page = current_app.config['SECURITY_POST_LOGIN_VIEW']

                connection.unbind()
                db.session.commit()
                return redirect(next_page)
            else:
                connection.unbind()
                flash("We couldn't log you in, please contact your administrator.")  # noqa

        else:
            flash("We couldn't log you in, please check your password.")

    return render_template(
        current_app.config['SECURITY_LOGIN_USER_TEMPLATE'],
        login_user_form=form
    )
