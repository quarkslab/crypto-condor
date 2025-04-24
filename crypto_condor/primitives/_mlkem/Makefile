# Detect host OS if not already set
ifndef HOST_OS
	ifeq ($(OS),Windows_NT)
		HOST_OS := Windows
	else
		HOST_OS := $(shell uname -s)
	endif
endif

ifeq ($(HOST_OS),Darwin)
	PATCH = ../cc-mlkem-ios.patch
else ifeq ($(HOST_OS),Linux)
	PATCH = ../cc-mlkem.patch
else
$(error Unsupported HOST_OS: $(HOST_OS))
endif

all: mlkem.patch

kyber:
	git clone https://github.com/pq-crystals/kyber.git && git -C kyber checkout 10b478fc3cc4ff6215eb0b6a11bd758bf0929cbd

mlkem.patch: kyber
	git -C kyber apply $(PATCH)