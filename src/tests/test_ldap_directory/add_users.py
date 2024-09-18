import ldap3
from ldap3 import Connection

def add_local_users(server, user, passwd, responses=None, n=20, unit_testing=False):
    responses = responses or []
    
    with Connection(server,
                    user, passwd,
                    client_strategy = ldap3.MOCK_SYNC if unit_testing else ldap3.SYNC) as conn:

        bind_base='ou=People,ou=Local,dc=example,dc=com'
    
        for uidNumber in range(n):
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
            
            if not unit_testing:
                responses.append( (dn, conn.result) )

            conn.modify(dn=dn,
                        changes={'userPassword': [(ldap3.MODIFY_ADD, ['secret123'])]})

            if not unit_testing:
                responses.append( (dn, conn.result) )

    

def add_external_users(server, user, passwd, responses=None, n=20, unit_testing=False):
    responses = responses or []
    
    with Connection(server,
                    user, passwd,
                    client_strategy = ldap3.MOCK_SYNC if unit_testing else ldap3.SYNC) as conn:
        bind_base='ou=People,ou=External,dc=example,dc=com'
    
        for uidNumber in range(n):
            dn = f'uid=external_user{uidNumber},' + bind_base
            conn.add(dn=dn,
                     object_class=['inetOrgPerson','shadowAccount'],
                     attributes={'sn': f'External User {uidNumber}',
                                 'cn': f'External User {uidNumber}',
                                 'displayName': f'External User {uidNumber}',
                                 'mail': f'externaluser_{uidNumber}@yahootmail.co.cz'
                                 })
                         
            if not unit_testing:
                responses.append( (dn, conn.result) )
            
            conn.modify(dn=dn,
                        changes={'userPassword': [(ldap3.MODIFY_ADD, ['secret123'])]})
            
            if not unit_testing:
                responses.append( (dn, conn.result) )

    

