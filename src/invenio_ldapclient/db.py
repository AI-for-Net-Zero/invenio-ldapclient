import uuid
from datetime import datetime

from werkzeug.local import LocalProxy
from flask import current_app

from invenio_accounts.models import User
from invenio_db import db

from invenio_accounts import __version__ as __accounts__version__

_security = LocalProxy(lambda: current_app.extensions["security"])
_datastore = LocalProxy(lambda: _security.datastore)


def _commit(response=None):
    _datastore.commit()
    return response


def update_user(user, username, email, full_name=None):
    user.email = email

    """
    Only update profile if these attribs are not already in app, since we can assume the user
    has updated their own profile - updates which would be over-written.

    Perhaps add one or two config keys to determine the behaviour

    What do we do if the user profile update fails?  Write to log - add invenio_logging

    Wait for integration test, but consider taking out the try ... except 
    full_name is brought from directory where this is guaranteed to be a valid string(?)
    """
    if full_name and not user.user_profile["full_name"]:
        with db.session.begin_nested():
            user.user_profile.update([], full_name=full_name)
            db.session.add(user)

    db.session.add(user)
    return


def add_user(username, email, full_name=None):
    kwargs = dict(
        username=username,
        email=email,
        # active=True,
        password=uuid.uuid4().hex,
        # confirmed_at=datetime.utcnow(),
        # verified_at=datetime.utcnow()
    )

    _datastore.create_user(**kwargs)
    _datastore.commit()

    user = User.query.filter_by(username=username).one_or_none()

    if int(__accounts__version__.split(".")[0]) >= 5:
        _datastore.verify_user(user)
    else:
        _datastore.activate_user(user)
        user.confirmed_at = datetime.utcnow()

    if full_name:
        with db.session.begin_nested():
            user.user_profile.update([], full_name=full_name)
            db.session.add(user)

    db.session.add(user)
    return user


def find_or_register_user(request_object):
    """
    Searches the app database for matching username and returns user object, if found. 
    Otherwise, adds user and email address obtained from directory.
    
    We assume (see dit module) that uid is a globally unique identifier for users in directory.

    If user with username = uid is found, we return the user object, otherwise, we add and confirm them.
    """
    username = request_object.get_username()
    email = request_object.get_email()

    # Search app db for user
    # 1. First, by username
    user = User.query.filter_by(username=username).one_or_none()

    #
    # Therefore, for the time being, search app db by email is superfluous.
    # --->
    if user:
        # We found the user - update their profile info with stuff from directory
        update_user(user, username, email)
        return user

    else:
        # We didn't find the user - create an entry in the app db with a dummy passwd
        user = add_user(username, email)
        return user
