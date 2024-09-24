import uuid

from werkzeug.local import LocalProxy
from flask import current_app

from invenio_accounts.models import User
from invenio_db import db
from .utils import config_value as cv

_security = LocalProxy(lambda: current_app.extensions['security'])
_datastore = LocalProxy(lambda: _security.datastore)

def _commit(response=None):
    _datastore.commit()
    return response

def update_user(user, form):
    username = form.username.data
    email = form.email
    full_name = form.full_name

    user.email = email # Email address needs to be in directory for login to succeed

    '''
    Only update profile if these attribs are not already in app, since we can assume the user
    has updated their own profile - updates which would be over-written.

    Perhaps add one or two config keys to determine the behaviour

    What do we do if the user profile update fails?  Write to log - add invenio_logging

    Wait for integration test, but consider taking out the try ... except 
    full_name is brought from directory where this is guaranteed to be a valid string(?)
    '''
    if full_name and not user.user_profile['full_name']:
        try:
            with db.session.begin_nested():
                user.user_profile.update([], full_name = full_name)
                db.session.add(user)
        except:
            pass # Do something, e.g., write to log

    db.session_add(user)
    return
        

def add_user(form):
    username = form.username.data
    email = form.email
    full_name = form.full_name

    kwargs = dict(username=username,
                  email=email,
                  active=True,
                  password=uuid.uuid4().hex)

    _datastore.create_user(**kwargs)
    
    user = User.query.filter_by(username=username).one_or_none()

    if full_name:
        try:
            with db.session.begin_nested():
                user.user_profile.update([], full_name = full_name)
                db.session.add(user)
        except:
            pass # Do something, e.g., write to log
        
    db.session_add(user)
    return user

def find_or_register_user(form):
    
    username = form.username.data
    email = form.email

    # Search app db for user
    # 1. First, by username
    user = User.query.filter_by(username=username).one_or_none()

    # <--- We're currently assuming
    #     form.username ---> (1 or 0) ---> uid (directory) ---> (1 or 0) ---> User.username, i.e.,
    #     
    #     (1) uid is a globally unique identifier for users in directory (which would be
    #         case when there is a single bind base
    #     (2) usernames in app db strictly match uid's in directory
    #
    # Therefore, for the time being, search app db by email is superfluous.
    # --->

    
    # 2. Then by email, if this wasn't successful (and we allow it in config)
    #if not user and cv('find_by_email'):
    #    user = User.query.filter_by(email=email).one_or_none()

    if user:
        # We found the user - update their profile info with stuff from directory
        update_user(user, form)
        return user

    else:
        # We didn't find the user - create an entry in the app db with a dummy passwd
        user = add_user(form)
        return user