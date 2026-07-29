CC ?= aarch64-linux-android21-clang
CFLAGS ?= -O2 -s -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2

all: xenoid-input

xenoid-input: xenoid_input.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f xenoid-input
