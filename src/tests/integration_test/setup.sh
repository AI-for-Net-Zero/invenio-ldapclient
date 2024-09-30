#!/bin/bash

# Has containerised slapd instance been built?
CONTAINER_NAME=`cat ldap_container_name`

container_has_ipv4 ()
{
    IP="$(lxc-info -i -H -n $1)"
    echo ${IP}
    test -n ${IP} && test ${IP} != "10.0.3.1" 
}

# Start ldap container & get ip address


lxc-unpriv-start -n ${CONTAINER_NAME} &> /dev/null

while ! container_has_ipv4 ${CONTAINER_NAME}; do
    echo "waiting for IP addr"
    sleep 1
done

IPADDR=${IP}
echo "LDAP server IP addr: "${IPADDR}
sed -ri "s/^(LDAP_SERVER_IP)\s*=\s*\S+.*/\1=\'${IPADDR}\'/" instance/config.py

# Initialise app db (in instance folder)
export INSTANCE_PATH=${PWD}/instance
flask --app minimal:create_app db init create --verbose


# Start app in dev server
flask --app minimal:create_app run --debug
