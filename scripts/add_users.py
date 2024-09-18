import os
from ldap3 import Server, Connection, MODIFY_ADD

HOST=os.environ.get('LDAP_URI')

server = Server(HOST)

with Connection(server, 'cn=admin,dc=example,dc=com', 'monkey') as conn:
    # Local users
    bind_base='ou=People,ou=Local,dc=example,dc=com'
    
    for uidNumber in range(20):
        dn = f'uid=user{uidNumber},' + bind_base
        conn.add(dn=dn,
                 object_class=['inetOrgPerson','posixAccount','shadowAccount'],
                 attributes={'homeDirectory': f'/home/testuser{uidNumber}',
                             'sn': f'User {uidNumber}',
                             'cn': f'User {uidNumber}',
                             'displayName': f'User {uidNumber}',
                             'uidNumber': uidNumber,
                             'gidNumber': 0,
                             'mail': f'user_{uidNumber}@example.com'
                             })
                         
        print(dn)
        print(conn.result)
        print(conn.response)

        conn.modify(dn=dn,
                    changes={'userPassword': [(MODIFY_ADD, ['secret123'])]})

        print(dn)
        print(conn.result)
        print(conn.response)

    # External users
    bind_base='ou=People,ou=External,dc=example,dc=com'
    
    for uidNumber in range(20):
        dn = f'uid=external_user{uidNumber},' + bind_base
        conn.add(dn=dn,
                 object_class=['inetOrgPerson','shadowAccount'],
                 attributes={'sn': f'External User {uidNumber}',
                             'cn': f'External User {uidNumber}',
                             'displayName': f'External User {uidNumber}',
                             'mail': f'externaluser_{uidNumber}@yahootmail.co.cz'
                             })
                         
        print(dn)
        print(conn.result)
        print(conn.response)

        conn.modify(dn=dn,
                    changes={'userPassword': [(MODIFY_ADD, ['secret123'])]})

        print(dn)
        print(conn.result)
        print(conn.response)

        
    dn = 'uid=invenio_acc,ou=Special,dc=example,dc=com'
    conn.add(dn=dn,
             object_class=['inetOrgPerson','shadowAccount'],
             attributes={'sn': f'Invenio Account',
                         'cn': f'Invenio Account',
                         'displayName': f'Invenio Account'
                         })
    
    print(dn)
    print(conn.result)
    print(conn.response)
    
    conn.modify(dn=dn,
                changes={'userPassword': [(MODIFY_ADD, ['secret123'])]})
    
    print(dn)
    print(conn.result)
    print(conn.response)
