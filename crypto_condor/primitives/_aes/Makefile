CFLAGS = -Wall -O2 -fPIC

# Detect host OS if not already set
ifndef HOST_OS
	ifeq ($(OS),Windows_NT)
		HOST_OS := Windows
	else
		HOST_OS := $(shell uname -s)
	endif
endif

# Set compiler, flags, and suffix based on OS
ifeq ($(HOST_OS),Darwin)
	CC      = clang
	LIBFLAGS = -dynamiclib
	LIBRARY_SUFFIX = .dylib
else ifeq ($(HOST_OS),Linux)
	CC      ?= gcc
	LIBFLAGS = -shared
	LIBRARY_SUFFIX = .so
else
$(error Unsupported HOST_OS: $(HOST_OS))
endif

TARGET = aes$(LIBRARY_SUFFIX)
OBJ = aes.o

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LIBFLAGS) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o *.so *.dll *.dylib
