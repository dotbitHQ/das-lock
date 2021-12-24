TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
DEBUG_FLAGS := -DCKB_C_STDLIB_PRINTF
CFLAGS := -Os -fPIC -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -I . -I deps/ckb-c-stdlib -I deps/ckb-c-stdlib/libc -I deps/ckb-c-stdlib/molecule -I deps/secp256k1/src -I deps/secp256k1 -I deps/ed25519/src -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3


PROTOCOL_HEADER := ./protocol.h
PROTOCOL_SCHEMA := ./blockchain.mol
PROTOCOL_VERSION := d75e4c56ffa40e17fd2fe477da3f98c5578edcd1
PROTOCOL_URL := https://raw.githubusercontent.com/nervosnetwork/ckb/${PROTOCOL_VERSION}/util/types/schemas/blockchain.mol

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make all"
	./tool/ckb-binary-patcher -i eth_sign.so.release -o ./build/release/eth_sign.so
	./tool/ckb-binary-patcher -i tron_sign.so.release -o ./build/release/tron_sign.so
	./tool/ckb-binary-patcher -i ckb_sign.so.release -o ./build/release/ckb_sign.so
	./tool/ckb-binary-patcher -i ed25519_sign.so.release -o ./build/release/ed25519_sign.so
	cp dispatch.release ./build/release/dispatch

debug-all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make debug_all"
	./tool/ckb-binary-patcher -i tron_sign.so.debug -o ./build/debug/tron_sign.so
	./tool/ckb-binary-patcher -i eth_sign.so.debug -o ./build/debug/eth_sign.so
	./tool/ckb-binary-patcher -i ckb_sign.so.debug -o ./build/debug/ckb_sign.so
	./tool/ckb-binary-patcher -i ed25519_sign.so.debug -o ./build/debug/ed25519_sign.so
	cp dispatch.debug ./build/debug/dispatch
	scp ./build/debug/dispatch ubuntu_root:/mnt/ckb/das-sandbox-testnet2/contracts/dispatch
	scp ./build/debug/dispatch ubuntu_root:/mnt/ckb/das-sandbox/contracts/dispatch

all: dispatch.release eth_sign.so.release ckb_sign.so.release tron_sign.so.release ed25519_sign.so.release

debug_all: dispatch.debug eth_sign.so.debug ckb_sign.so.debug tron_sign.so.debug ed25519_sign.so.debug

dispatch.debug: dispatch.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -o $@ $<

dispatch.release: dispatch.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

ckb_sign.so.debug: ckb_sign.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<

ckb_sign.so.release: ckb_sign.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $<

tron_sign.so.debug: tron_sign.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<

tron_sign.so.release: tron_sign.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $<

eth_sign.so.debug: eth_sign.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<

eth_sign.so.release: eth_sign.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $<

ed25519_sign.so.debug: ed25519_sign.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $^

ed25519_sign.so.release: ed25519_sign.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $<

ckb_multi_sign.so.debug: ckb_multi_sign.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<

ckb_multi_sign.so.release: ckb_multi_sign.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $<

${PROTOCOL_HEADER}: ${PROTOCOL_SCHEMA}
	${MOLC} --language c --schema-file $< > $@

${PROTOCOL_SCHEMA}:
	curl -L -o $@ ${PROTOCOL_URL}
