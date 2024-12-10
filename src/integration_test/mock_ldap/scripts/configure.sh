#!/bin/bash

LDAP_PASSWD=$1

cp -R /home/host/config /tmp

ldapadd -x -D 'cn=admin,dc=example,dc=com' -H ldapi:/// -w ${LDAP_PASSWD} \
	-f /tmp/config/add_org_units.ldif


GID_NUMBER=1

for GROUP_NAME in red green blue
do
    sed """
    s/<group_name>/${GROUP_NAME}/
    s/<gid_number>/${GID_NUMBER}/
    s/<bind_base>/ou=Groups,ou=Local,dc=example,dc=com/
    """ tmp/config/add_group.ldif.tmpl | \

	ldapadd -x -D 'cn=admin,dc=example,dc=com' -w ${LDAP_PASSWD} -H ldapi:///

    echo $((GID_NUMBER++)) > /dev/null
done

for UID_NUMBER in $(seq 0 9)
do
    sed """
    s/<user_uid>/user_${UID_NUMBER}/
    s/<display_name>/User ${UID_NUMBER}/
    s/<uid_number>/${UID_NUMBER}/
    s/<gid_number>/0/
    s/<bind_base>/ou=People,ou=Local,dc=example,dc=com/
    """ tmp/config/add_internal_user.ldif.tmpl | \

	ldapadd -x -D 'cn=admin,dc=example,dc=com'  -w ${LDAP_PASSWD} -H ldapi:///
    
    ldappasswd -x -D 'cn=admin,dc=example,dc=com' -w ${LDAP_PASSWD} -H ldapi:/// \
	       -s secret123 uid=user_${UID_NUMBER},ou=People,ou=Local,dc=example,dc=com
    
done


for UID_NUMBER in $(seq 21 25)
do
    sed """
    s/<user_uid>/external_user_${UID_NUMBER}/
    s/<bind_base>/ou=People,ou=External,dc=example,dc=com/
    s/<display_name>/External User ${UID_NUMBER}/
    """ tmp/config/add_external_user.ldif.tmpl | \

	ldapadd -x -D 'cn=admin,dc=example,dc=com'  -w ${LDAP_PASSWD} -H ldapi:///

    ldappasswd -x -D 'cn=admin,dc=example,dc=com' -w ${LDAP_PASSWD} -H ldapi:/// \
	       -s secret123 uid=external_user_${UID_NUMBER},ou=People,ou=External,dc=example,dc=com

done


echo """
dn: cn=green,ou=Groups,ou=Local,dc=example,dc=com
changetype: modify
add: memberUid
memberUid: user_0
memberUid: user_1
memberUid: user_2
memberUid: user_3
memberUid: user_4
memberUid: user_5
""" | ldapmodify -x -D 'cn=admin,dc=example,dc=com' -w ${LDAP_PASSWD} -H ldapi:///


echo """
dn: cn=red,ou=Groups,ou=Local,dc=example,dc=com
changetype: modify
add: memberUid
memberUid: user_8
memberUid: user_9
""" | ldapmodify -x -D 'cn=admin,dc=example,dc=com' -w ${LDAP_PASSWD} -H ldapi:///

echo """
dn: cn=blue,ou=Groups,ou=Local,dc=example,dc=com
changetype: modify
add: memberUid
memberUid: external_user_21
memberUid: external_user_22
memberUid: external_user_23
""" | ldapmodify -x -D 'cn=admin,dc=example,dc=com' -w ${LDAP_PASSWD} -H ldapi:///


#Local user 0 has no email address
echo """
dn: uid=user_0,ou=People,ou=Local,dc=example,dc=com
changetype: modify
delete: mail
mail: user_0@example.com
""" | ldapmodify -x -D 'cn=admin,dc=example,dc=com' -w ${LDAP_PASSWD} -H ldapi:///

#Local user 1 has an extra email address
echo """
dn: uid=user_1,ou=People,ou=Local,dc=example,dc=com
changetype: modify
add: mail
mail: user_1_extra@example.com
""" | ldapmodify -x -D 'cn=admin,dc=example,dc=com' -w ${LDAP_PASSWD} -H ldapi:///

#An external user has the same uid as an internal user
echo """
dn: uid=user_2,ou=People,ou=External,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: shadowAccount
displayName: Conflicting Uid 2
sn: user_2
cn: user_2
mail: user_2@mischief.com
""" | ldapadd  -x -D 'cn=admin,dc=example,dc=com' -w ${LDAP_PASSWD} -H ldapi:///

#And let's alias a couple of users
echo """
dn: uid=coffee_machine_repair,ou=Special,dc=example,dc=com
objectClass: alias
objectClass: extensibleObject
aliasedObjectName: uid=user_5,ou=People,ou=Local,dc=example,dc=com
mail: the_big_I_AM@bttinternet.com

dn: uid=user6_alt,ou=Special,dc=example,dc=com
objectClass: alias
objectClass: extensibleObject
aliasedObjectName: uid=user_6,ou=People,ou=Local,dc=example,dc=com
mail: no_scruggs@postmister.co.uk
""" | ldapadd -x -D 'cn=admin,dc=example,dc=com'  -w ${LDAP_PASSWD} -H ldapi:///
