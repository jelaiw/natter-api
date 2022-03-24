#!/bin/sh
echo "Register demo user."
curl -i -d @register_demo_user.json -H 'Content-Type: application/json' https://localhost:4567/users
echo "\nCreate test space (as demo user)."
curl -u demo:password -i -d @create_space.json -H 'Content-Type: application/json' https://localhost:4567/spaces
echo "\nPost a message."
curl -u demo:password -i -d @hello_world_demo_user_message.json -H 'Content-Type: application/json' https://localhost:4567/spaces/1/messages
#curl https://localhost:4567/logs | jq
