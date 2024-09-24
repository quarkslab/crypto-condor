CFLAGS = -Wall

all: test

aes_wrapper: aes_wrapper.c aes/aes.c
	$(CC) $(CFLAGS) -o aes_wrapper $^

sha_wrapper: sha_wrapper.c sha/sha3.c sha/sha3.h
	$(CC) $(CFLAGS) -o sha_wrapper $^

# The leading dash ignores errors, so that even if the first test fails the
# second one will run.
test: aes_wrapper sha_wrapper
	-crypto-condor-cli test wrapper AES aes_wrapper CBC-PKCS7 256
	-crypto-condor-cli test wrapper SHA sha_wrapper SHA3-256

clean:
	rm -f aes_wrapper sha_wrapper
