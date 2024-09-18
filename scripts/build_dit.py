import os
from ldap3 import Server, Connection

HOST=os.environ.get('LDAP_URI')

server = Server(HOST)

with Connection(server, 'cn=admin,dc=example,dc=com', 'monkey') as conn:
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
        
        
        print(dn)
        print(conn.result)
        print(conn.response)
             
    



                


    

    









