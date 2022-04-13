#!/bin/sh
echo "Register demo user."
curl -i -d @register_demo_user.json -H 'Content-Type: application/json' https://localhost:4567/users
echo "\nEstablish a session (cookie-based)."
curl -c /tmp/cookies -u demo:password -i -H 'Content-Type: application/json' -X POST https://localhost:4567/sessions
echo "\nCreate test space (as part of existing demo user session)."
curl -b /tmp/cookies -i -d @create_space.json -H 'Content-Type: application/json' https://localhost:4567/spaces
#curl https://localhost:4567/logs | jq
