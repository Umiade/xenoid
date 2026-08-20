# xenoid-ebpf — host-side path-hide (clang -target bpf + libbpf loader)
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' -e 's/armv.*/arm/')
INCLUDES := -I. -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS := -target bpf -O2 -g -ffile-prefix-map=$(CURDIR)=. -fdebug-prefix-map=$(CURDIR)=. -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -Wall
USER_CFLAGS := -O2 -g -ffile-prefix-map=$(CURDIR)=. -fdebug-prefix-map=$(CURDIR)=. -Wall $(INCLUDES)
USER_LDFLAGS := -lbpf -lelf -lz

.PHONY: all clean vmlinux skeleton

all: xenoid-ebpf-loader

vmlinux.h:
	@if [ ! -e /sys/kernel/btf/vmlinux ]; then echo "missing /sys/kernel/btf/vmlinux"; exit 1; fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

xenoid_pathhide.bpf.o: xenoid_pathhide.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

xenoid_pathhide.skel.h: xenoid_pathhide.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

xenoid-ebpf-loader: loader.c xenoid_pathhide.skel.h
	$(CLANG) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

clean:
	rm -f xenoid_pathhide.bpf.o xenoid_pathhide.skel.h xenoid-ebpf-loader vmlinux.h
