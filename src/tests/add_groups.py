import ldap3
from ldap3 import Connection

def add_groups(server, user, passwd, responses=None,
               groups = ['red', 'green', 'blue'],
               n = 20,
               unit_testing=False):
    
    responses = responses or []
    
    with Connection(server,
                    user, passwd,
                    client_strategy = ldap3.MOCK_SYNC if unit_testing else ldap3.SYNC) as conn:

        bind_base = 'ou=Groups,ou=Local,dc=example,dc=com'

        for i, cn in enumerate(groups):
            dn = f'cn={cn},' + bind_base
            conn.add(dn=dn,
                     object_class='posixGroup',
                     attributes={'gidNumber': i,
                                 'memberUid': [f'user{uid}' for uid in range(n)]})
            
            if not unit_testing:
                responses.append( (dn, conn.result) )

    

    









