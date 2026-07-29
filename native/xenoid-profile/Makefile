CC ?= aarch64-linux-android21-clang
CFLAGS ?= -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2
all: xenoid-profile
xenoid-profile: xenoid_profile.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f xenoid-profile
