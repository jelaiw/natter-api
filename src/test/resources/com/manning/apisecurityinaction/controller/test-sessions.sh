#!/bin/sh
echo "Register demo user."
curl -i -d @register_demo_user.json -H 'Content-Type: application/json' https://localhost:4567/users
echo "\nEstablish a session."
curl -u demo:password -i -H 'Content-Type: application/json' -X POST https://localhost:4567/sessions
#curl https://localhost:4567/logs | jq
