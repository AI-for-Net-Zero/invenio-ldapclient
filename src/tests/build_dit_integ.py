import os
import json

from ldap3 import Server

from add_org_units import add_organisational_units
from add_users import add_local_users, add_external_users
from add_groups import add_groups
from final import final

if __name__ == '__main__':
    url=os.environ.get('LDAP_URL', None)
    user=os.environ.get('LDAP_USER', None)
    passwd=os.environ.get('LDAP_PSSWD', None)

    if not url:
        exit('Set LDAP_URL')

    if not user:
        exit('Set LDAP_USER')

    if not passwd:
        exit('Set LDAP_PSSWD')

    server = Server(url)

    r = []
    
    add_organisational_units(server, user, passwd, r)
    add_local_users(server, user, passwd, r)
    add_external_users(server, user, passwd, r)
    add_groups(server, user, passwd, r)
    final(server, user, passwd, r)

    with open('build_dit_integ.out', 'w') as f:
        for dn, resp in r:
            if resp.get('result', 1) != 0:
                f.write('%s:\n' %dn)
                json.dump(resp, f)



        
