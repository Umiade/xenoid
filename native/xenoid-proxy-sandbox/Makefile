CC ?= cc
CPPFLAGS ?= -D_FORTIFY_SOURCE=3
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror -fPIE -fstack-protector-strong
LDFLAGS ?= -static-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
PREFIX ?= /usr
LIBEXECDIR ?= $(PREFIX)/libexec

.PHONY: all clean install

all: xenoid-proxy-sandbox

xenoid-proxy-sandbox: xenoid_proxy_sandbox.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS)

install: xenoid-proxy-sandbox
	install -d -m 0755 $(DESTDIR)$(LIBEXECDIR)
	install -o root -g root -m 0555 xenoid-proxy-sandbox $(DESTDIR)$(LIBEXECDIR)/xenoid-proxy-sandbox

clean:
	rm -f xenoid-proxy-sandbox
