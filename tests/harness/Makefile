CC ?= gcc
CFLAGS = -Wall -O2 -fPIC
LDFLAGS = -lssl -lcrypto

%.so: %.o
	$(CC) -shared $(CFLAGS) $< -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

clean:
	rm -f *.so
