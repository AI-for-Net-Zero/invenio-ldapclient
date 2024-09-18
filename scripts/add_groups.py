import os
from ldap3 import Server, Connection, MODIFY_ADD

HOST=os.environ.get('LDAP_URI')

server = Server(HOST)

with Connection(server, 'cn=admin,dc=example,dc=com', 'monkey') as conn:
    bind_base = 'ou=Groups,ou=Local,dc=example,dc=com'

    for colour in ['red', 'green', 'blue']:
        dn = f'cn={colour},' + bind_base
        conn.add(dn=dn,
                 object_class='posixGroup',
                 attributes={'gidNumber': 0,
                             'memberUid': [f'user{uid}' for uid in range(20)]})

        print(dn)
        print(conn.result)
        print(conn.response)

    

    









