# Stop app in dev server

# Destroy app db
flask --app minimal:create_app db destroy --yes-i-know

# Stop ldap server
CONTAINER_NAME=`cat ldap_container_name`
lxc-stop -n ${CONTAINER_NAME} &> /dev/null

