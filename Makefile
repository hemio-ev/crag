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

fixerr:
	sed -i "s/^mapM$$/  mapM/g" src/Network/ACME/Types.hs

format-code: fixerr $(HS)
	sed -i "s/^mapM$$/  mapM/" src/Network/ACME/Types.hs

$(HS):
	@./.cabal-sandbox/bin/hlint $@
	@./.cabal-sandbox/bin/hindent $@
