CC ?= gcc
CFLAGS = -Wall -O2 -fPIC

all: aes.so

%.so: %.o
	$(CC) -shared $(CFLAGS) $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.so

