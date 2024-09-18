import ldap3
from ldap3 import Connection

def add_organisational_units(server, user, passwd, responses=None, unit_testing=False):
    _responses = [] if responses is None else responses
    
    with Connection(server,
                    user, passwd,
                    client_strategy = ldap3.MOCK_SYNC if unit_testing else ldap3.SYNC) as conn:
        for dn in ['ou=Special,dc=example,dc=com',
                   'ou=Local,dc=example,dc=com',
                   'ou=External,dc=example,dc=com',
                   'ou=People,ou=Local,dc=example,dc=com',
                   'ou=Groups,ou=Local,dc=example,dc=com',
                   'ou=People,ou=External,dc=example,dc=com',
                   'ou=Groups,ou=External,dc=example,dc=com',
                   ]:
          
            conn.add(dn=dn,
                     object_class='organizationalUnit')

            if not unit_testing:
                _responses.append( (dn, conn.result) )




                


    

    









