#!/bin/bash

export GOPATH=`pwd`/gopath
src="$GOPATH/src/github.com/letsencrypt/boulder"

cd "$src"
docker-compose run \
    -e FAKE_DNS=172.17.0.1 \
    -e BOULDER_CONFIG_DIR=test/config-next \
    --service-ports boulder ./start.py
