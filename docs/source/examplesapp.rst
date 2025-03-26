..
    Copyright (C) 2018 Galter Health Sciences Library & Learning Center.
    Invenio-LDAPClient is free software; you can redistribute it and/or modify it
    under the terms of the MIT License; see LICENSE file for more details.


Example applications
====================

There are two example applications `minimal` and `minimal_rest` - these require a directory server instance to be accessible.

First, install the packages

::

   cd </path/to/>invenio-ldapclient
   python -m venv .venv
   . .venv/bin/activate
   pip install --upgrade pip && pip install -e '.[dev]'


minimal
^^^^^^^
   
Set up the db and run::
   
   export INSTANCE_PATH=<absolute_instance_path>

   flask --app minimal db init create
   flask --app minimal run --debug


Navigate to `<http://127.0.0.1:5000>`_ in a web-browser.


minimal_rest
^^^^^^^^^^^^

Set up the db and run::
   
   export INSTANCE_PATH=<absolute_instance_path>

   flask --app minimal_rest db init create
   flask --app minimal_rest run -p 5001 --debug


Then, to log in::

  curl -X POST -H "Content-type: application/json" \
  -d '{"username": <username>, "password": <password>}' \
  http://127.0.0.1:5001/login --cookie-jar user.cookie


::

   {
   "confirmed_at": "2025-03-26T09:01:28.046843",
   "email": "user_1@example.com",
   "id": 1,
   "last_login_at": "2025-03-26T09:02:47.646597",
   "roles": []
   }

Who am I?::

  curl http://127.0.0.1:5001/me --cookie user.cookie

::

   {
   "confirmed_at": "2025-03-26T09:01:28.046843",
   "email": "user_1@example.com",
   "id": 1,
   "last_login_at": "2025-03-26T09:02:47.646597",
   "roles": []
   }


Log out::

  curl -X POST http://127.0.0.1:5001/logout --cookie user.cookie

::

   {
   "message": "User logged out."
   }


   




