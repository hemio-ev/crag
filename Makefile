export GOPATH := $(shell pwd)/gopath

PEBBLE_PATH = $(GOPATH)/src/github.com/letsencrypt/pebble
HS = $(shell find src/ test/ -name '*.hs')

.PHONY: test $(HS)

recompile:
	cabal build --ghc-options=-fforce-recomp

configure-tests:
	cabal configure --enable-tests

configure-coverage:
	cabal configure --enable-tests --enable-coverage

test:
	cabal configure --disable-optimi --enable-tests
	cabal test --show-details=direct --test-option=--color=always

pebble: pebble-get pebble-install

pebble-get:
	go get -d -u github.com/letsencrypt/pebble/...

pebble-install:
	cd $(PEBBLE_PATH); go install ./...

fixerr:
	sed -i "s/^mapM$$/  mapM/g" src/Network/ACME/Object.hs

format-code: fixerr $(HS)
	sed -i "s/^mapM$$/  mapM/" src/Network/ACME/Object.hs

$(HS):
	@./.cabal-sandbox/bin/hlint $@
	@./.cabal-sandbox/bin/hindent $@
