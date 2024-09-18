import os
import ldap3
from ldap3 import Server, Connection

HOST=os.environ.get('LDAP_URI')

server = Server(HOST)

with Connection(server, 'cn=admin,dc=example,dc=com', 'monkey') as conn:
    #Local user 0 has no email address
    dn='uid=user0,ou=People,ou=Local,dc=example,dc=com',
    conn.modify(dn=dn,
                changes={'mail': [(ldap3.MODIFY_DELETE, 'user_0@example.com')]})

    print(dn)
    print(conn.result)
    print(conn.response)

    #Local user 1 has an extra email address
    dn='uid=user1,ou=People,ou=Local,dc=example,dc=com',
    conn.modify(dn=dn,
                changes={'mail': [(ldap3.MODIFY_ADD, 'user_1_extra@example.com')]})

    print(dn)
    print(conn.result)
    print(conn.response)

    #An external user has same uid as an internal one
    dn='uid=user2,ou=People,ou=External,dc=example,dc=com'
    conn.add(dn=dn,
             object_class=['inetOrgPerson','shadowAccount'],
             attributes={'sn': 'User 2',
                         'cn': 'User 2',
                         'displayName': 'User 2',
                         'mail': 'User_2@yahootmail.co.cz'
                         })

    print(dn)
    print(conn.result)
    print(conn.response)

    #And for kicks, let's alias a couple of users
    dn='uid=user5,ou=Special,dc=example,dc=com'
    conn.add(dn=dn,
             object_class=['alias','extensibleObject'],
             attributes={'aliasedObjectName': 'uid=user5,ou=People,ou=Local,dc=example,dc=com',
                         'mail': 'the_big_I_AM@bttinternet.com'})

    print(dn)
    print(conn.result)
    print(conn.response)

    dn='uid=user6_alt,ou=Special,dc=example,dc=com'
    conn.add(dn=dn,
             object_class=['alias','extensibleObject'],
             attributes={'aliasedObjectName': 'uid=user6,ou=People,ou=Local,dc=example,dc=com',
                         'mail': 'no_scruggs@postmister.co.uk'})

    print(dn)
    print(conn.result)
    print(conn.response)


    
    


    
