# Detect host OS if not already set
ifndef HOST_OS
	ifeq ($(OS),Windows_NT)
		HOST_OS := Windows
	else
		HOST_OS := $(shell uname -s)
	endif
endif

ifeq ($(HOST_OS),Darwin)
	PATCH = ../cc-mldsa-ios.patch
else ifeq ($(HOST_OS),Linux)
	PATCH = ../cc-mldsa.patch
else
$(error Unsupported HOST_OS: $(HOST_OS))
endif

all: mldsa

dilithium:
	git clone https://github.com/pq-crystals/dilithium.git && git -C dilithium checkout 444cdcc84eb36b66fe27b3a2529ee48f6d8150c2

mldsa: dilithium
	git -C dilithium apply $(PATCH)
	

