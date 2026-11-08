CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
LDLIBS_CRYPTO = -lcrypto -pthread
NFQ_FLAGS = $(shell pkg-config --cflags --libs libnetfilter_queue 2>/dev/null)
CPPFLAGS ?= -Iinclude

COMMON_SOURCES = src/packet.c src/checksum.c src/crypto.c

.PHONY: all test device clean

all: test

test: test_packet
	./test_packet

test_packet: tests/test_packet.c $(COMMON_SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS_CRYPTO)

device: secure_device

secure_device: src/secure_device.c $(COMMON_SOURCES)
	@test -n "$(NFQ_FLAGS)" || (echo "libnetfilter_queue development files are required; install libnetfilter-queue-dev" >&2; exit 1)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(NFQ_FLAGS) $(LDLIBS_CRYPTO)

clean:
	rm -f test_packet secure_device *.o
