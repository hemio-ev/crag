HS = $(shell find app/ src/ test/ -name '*.hs')


.PHONY: test $(HS)

test:
	cabal test --show-details=always --test-option=--color=always

format-code: $(HS)

$(HS):
	@./.cabal-sandbox/bin/hindent $@
