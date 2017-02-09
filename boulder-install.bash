#!/bin/bash

export GOPATH=./gopath
src="$GOPATH/src/github.com/letsencrypt/boulder"

git clone https://github.com/letsencrypt/boulder/ "$src"
cd "$src"
docker-compose build

