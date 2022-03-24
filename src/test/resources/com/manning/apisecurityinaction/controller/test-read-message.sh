#!/bin/sh
echo "Register demo user."
curl -i -d @register_demo_user.json -H 'Content-Type: application/json' https://localhost:4567/users
echo "\nCreate test space (as demo user)."
curl -u demo:password -i -d @create_space.json -H 'Content-Type: application/json' https://localhost:4567/spaces
echo "\nRegister demo2 user."
curl -i -d @register_demo2_user.json -H 'Content-Type: application/json' https://localhost:4567/users
echo "\nAttempt to read message from test space (as demo2 user)."
curl -u demo2:password -i https://localhost:4567/spaces/1/messages/1
echo "\nNOTE TO TESTER: Expect a 403 status code (as demo2 user does not have perms)."
#curl https://localhost:4567/logs | jq
