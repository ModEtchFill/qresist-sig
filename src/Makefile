# Native qsignify: liboqs (ML-DSA) + OpenSSL (Ed25519).
#
# liboqs is expected at ../third_party/liboqs (see scripts/build-liboqs.sh),
# or set LIBOQS=/path/to/prefix.

CC ?= cc
LIBOQS ?= $(abspath $(CURDIR)/../third_party/liboqs)

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Wpedantic -I$(LIBOQS)/include
LDFLAGS += -L$(LIBOQS)/lib -Wl,-rpath,$(LIBOQS)/lib
LDLIBS += -loqs -lcrypto

all: qsignify

qsignify: qsignify.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

test: qsignify
	./qsignify -G -a Q2 -p /tmp/qst.pub -s /tmp/qst.sec
	printf 'hello\n' > /tmp/qst.msg
	./qsignify -S -s /tmp/qst.sec -m /tmp/qst.msg -x /tmp/qst.sig
	./qsignify -V -p /tmp/qst.pub -m /tmp/qst.msg -x /tmp/qst.sig

clean:
	rm -f qsignify

.PHONY: all test clean
