#!/bin/bash

# Start ldap container & get ip address
lxc-unpriv-start ldap2_debian_bookworm_amd64 &> /dev/null
IPADDR=`lxc-info -H -i -n ldap2_debian_bookworm_amd64`
echo "LDAP server IP addr: "${IPADDR}
sed -ri "s/^(LDAP_SERVER_IP)\s*=\s*\S+.*/\1=\'${IPADDR}\'/" instance/config.py

# Initialise app db (in instance folder)
export INSTANCE_PATH=${PWD}/instance
flask --app minimal:create_app db init create --verbose


#echo ${INSTANCE_PATH} 
# Start app in dev server
