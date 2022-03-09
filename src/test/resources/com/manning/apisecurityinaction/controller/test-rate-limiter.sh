#!/usr/bin/zsh

for i in {1..5}
do
	curl -i -d @valid_post_data.json -H 'Content-Type: application/json' http://localhost:4567/spaces
done
