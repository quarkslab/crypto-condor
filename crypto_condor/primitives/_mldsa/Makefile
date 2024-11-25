all: mldsa.zip

dilithium:
	git clone https://github.com/pq-crystals/dilithium.git && git -C dilithium checkout 444cdcc84eb36b66fe27b3a2529ee48f6d8150c2

mldsa.zip: dilithium
	git -C dilithium apply ../cc-mldsa.patch
	zip $@ dilithium/ref/*.c dilithium/ref/*.h dilithium/ref/Makefile

cc-mldsa.patch:
	git -C dilithium diff >$@
