#!/bin/sh
echo "Register demo user."
curl -i -d @register_demo_user.json -H 'Content-Type: application/json' https://localhost:4567/users
echo "\nCreate test space (as demo user)."
curl -u demo:password -i -d @create_space.json -H 'Content-Type: application/json' https://localhost:4567/spaces
echo "\nPost a message as demo user."
curl -u demo:password -i -d @hello_world_demo_user_message.json -H 'Content-Type: application/json' https://localhost:4567/spaces/1/messages
echo "\nRegister demo2 user."
curl -i -d @register_demo2_user.json -H 'Content-Type: application/json' https://localhost:4567/users
echo "\nPause to avoid triggering rate-limiting protection. :-D"
sleep 2
echo "\nAdd demo2 user (as new member) to test space."
curl -u demo:password -i -d @add_member_demo2_user.json -H 'Content-Type: application/json' https://localhost:4567/spaces/1/members
echo "\nRead hello world message from test space as demo2 user."
curl -u demo2:password -i https://localhost:4567/spaces/1/messages/1
#curl https://localhost:4567/logs | jq
