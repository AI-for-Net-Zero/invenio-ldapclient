#!/bin/bash

LDAP_PASSWD=$1

export DEBIAN_FRONTEND=noninteractive

apt-get update && apt-get -y install slapd

PASSWD_HASH=$(slappasswd -n -s ${LDAP_PASSWD})

# Change admin password
echo """
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcRootPW
olcRootPW: ${PASSWD_HASH}
""" | tee /tmp/passwd_change.ldif

ldapmodify -Y EXTERNAL -f /tmp/passwd_change.ldif -H ldapi:///

# Change suffix
echo """
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: dc=example,dc=com
-
replace: olcRootDN
olcRootDN: cn=admin,dc=example,dc=com
""" | tee /tmp/suffix.ldif

ldapmodify -Y EXTERNAL -f /tmp/suffix.ldif -H ldapi:///

