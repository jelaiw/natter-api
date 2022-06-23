#!/bin/sh
MAC=$(curl -u demo:changeit -H 'Content-Type: application/json' -d @create_space.json https://localhost:4567/spaces | jq -r '.["messages-rw"]' | cut -d= -f2)
echo $MAC
