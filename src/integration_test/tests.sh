#!/bin/bash

set -u

export INSTANCE_PATH=$1

ROOT="http://localhost:5000"


CSRF=$(curl -X GET $ROOT/login/?next=/welcome |\
	   sed -rn 's/^.*csrf_token.*value="(.*)".*>/\1/p')


DATA='{"username": "user_1", "password": "secret123", "csrf_token": '$'"'$CSRF$'"''}'


curl -X POST $ROOT/login/?next=/welcome \
     -H "content-type: application/json" \
     -d "$DATA"

