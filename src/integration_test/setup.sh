#!/bin/bash

# Assumes test ldap server is reachable via hostname - "mock-ldap"
set -u

export INSTANCE_PATH=$1


flask --app minimal:create_app db destroy --yes-i-know init create --verbose

# Start app in dev server
nohup flask --app minimal:create_app run --debug &
