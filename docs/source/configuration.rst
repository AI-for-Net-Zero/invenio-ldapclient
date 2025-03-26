..
    Copyright (C) 2018 Galter Health Sciences Library & Learning Center.
    Invenio-LDAPClient is free software; you can redistribute it and/or modify it
    under the terms of the MIT License; see LICENSE file for more details.


Configuration
=============

.. automodule:: invenio_ldapclient.config
   :members:

Setting the following config keys overrides the default messages returned to the client in the event that authentication fails

When no users with `<username>` are found in directory::

  LDAPCLIENT_MSG_NO_USERS
  
When two or more users with `<username>` are found in directory::
  
  LDAPCLIENT_MSG_DUP_USERS

Invalid password for `<username>`::
  
  LDAPCLIENT_MSG_PASSWD

When no email address found in directory::
  
  LDAPCLIENT_MSG_NO_EMAIL

When <username> not found in required access group(s)::

  LDAPCLIENT_MSG_NO_ACCESS
      
