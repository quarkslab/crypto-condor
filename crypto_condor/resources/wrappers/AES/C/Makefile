# Change the compiler or flags with these variables.
CC := gcc
CFLAGS := -Wall -O2 -g

# Key length is 0 by default, which means all three possible sizes.
KEYLEN ?= 0

# Find all C source files to compile
SRCS := $(shell find $(SRC_DIRS) -name '*.c')

# From SRCS deduce the resulting object files.
OBJS := $(SRCS:%.c=%.o)

all: main

main: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Compile every .c file into a .o file.
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: main
ifeq ($(MODE),)
	@echo "No mode of operation defined, see 'make help'"; exit 1
else
	crypto-condor-cli run AES --language C --mode $(MODE) --key-length $(KEYLEN)
endif

help:
	@echo "This Makefile compiles the aes_wrapper, as well as other .c source files in this directory."
	@echo
	@echo "To run the wrapper, you have to indicate which mode of operation to test."
	@echo "For example, to run an AES-128-CBC implementation:"
	@echo "$$ make run MODE=CBC KEYLEN=128"
	@echo
	@echo "Note that KEYLEN is used to indicate a key length if the implementation only supports one."
	@echo "The default is 0 which means all three possible length (128, 192, 256) are used."

clean:
	rm -f main *.o
