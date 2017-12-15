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

format-code: $(HS)

$(HS):
	@./.cabal-sandbox/bin/hlint $@
	@./.cabal-sandbox/bin/hindent $@
