# Change the compiler or flags with these variables.
#CC := gcc
#CFLAGS := -Wall -O2

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

clean:
	rm -f main *.o
