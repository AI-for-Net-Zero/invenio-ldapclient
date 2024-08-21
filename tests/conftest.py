# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Galter Health Sciences Library & Learning Center.
#
# Invenio-LDAPClient is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pytest configuration."""

from __future__ import absolute_import, print_function

import shutil
import tempfile

import pytest
from flask import Flask
from flask_babel import Babel
from invenio_i18n import InvenioI18N


@pytest.fixture()
def instance_path():
    """Temporary instance path."""
    path = tempfile.mkdtemp()
    yield path
    shutil.rmtree(path)


@pytest.fixture()
def app(instance_path):
    app_ = Flask('testapp', instance_path=instance_path)

    app_.config.update(
        SECRET_KEY='SECRET_KEY',
        TESTING=True,
    )

    Babel(app_)
    InvenioI18N(app_)

    with app_.app_context():
        yield app_
            
