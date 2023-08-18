TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
DEBUG_FLAGS := $(empty)
CFLAGS ?= -Os -fPIC -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -I . -I deps/ckb-c-stdlib -I deps/ckb-c-stdlib/libc -I deps/ckb-c-stdlib/molecule -I deps/secp256k1/src -I deps/secp256k1  -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function
#CFLAGS := -DSHARED_LIBRARY -Os -fPIC -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -I . -I deps/ckb-c-stdlib -I deps/ckb-c-stdlib/libc -I deps/ckb-c-stdlib/molecule -I deps/secp256k1/src -I deps/secp256k1 -I deps/ed25519/src -I cryptos -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections

LIBECC_PATH := deps/libecc-riscv-optimized
SECP256R1_DEP := ${LIBECC_PATH}/build/libarith.a ${LIBECC_PATH}/build/libec.a ${LIBECC_PATH}/build/libsign.a
CFLAGS_LIBECC := -fPIC -O3 -fno-builtin -DUSER_NN_BIT_LEN=256 -DWORDSIZE=64 -DWITH_STDLIB -DWITH_BLANK_EXTERNAL_DEPENDENCIES -DCKB_DECLARATION_ONLY -DWITH_LL_U256_MONT
CFLAGS_LINK_TO_LIBECC := -fno-builtin -DWORDSIZE=64 -DWITH_STDLIB -DWITH_BLANK_EXTERNAL_DEPENDENCIES -fno-builtin-printf -I ${LIBECC_PATH}/src -I ${LIBECC_PATH}/src/external_deps



# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
#BUILDER_DOCKER := yuluyi/ckb-dev-all-in-one:0.1.0-amd64
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3


PROTOCOL_HEADER := c/protocol.h
PROTOCOL_SCHEMA := c/blockchain.mol
PROTOCOL_VERSION := d75e4c56ffa40e17fd2fe477da3f98c5578edcd1
PROTOCOL_URL := https://raw.githubusercontent.com/nervosnetwork/ckb/${PROTOCOL_VERSION}/util/types/schemas/blockchain.mol

contract_entry := dispatch
dyn_libs := ckb_sign tron_sign eth_sign ed25519_sign ckb_multi_sign doge_sign
webauthn_lib := webauthn_sign

contract_entry_targets = $(foreach file, $(contract_entry), release_$(file) debug_$(file))
contract_entry_files = $(foreach file, $(contract_entry), build/release/$(file) build/debug/$(file))

dyn_lib_targets = $(foreach file, $(dyn_libs), release_$(file) debug_$(file))
dyn_lib_files = $(foreach file, $(dyn_libs), build/release/$(file).so build/debug/$(file).so)

webauthn_lib_targets = $(foreach file, $(webauthn_lib), release_$(file) debug_$(file))
webauthn_lib_files = $(foreach file, $(webauthn_lib), build/release/$(file).so build/debug/$(file).so)


.PHONY: ckb-binary-patcher
ckb-binary-patcher:
ifeq ($(shell which cargo),)
	@echo "cargo not found"
	cp deps/ckb-binary-patcher/target/release/ckb-binary-patcher /usr/local/bin
else
	@echo "cargo found"
	#cargo clean --manifest-path ./deps/ckb-binary-patcher/Cargo.toml
	cargo install --path deps/ckb-binary-patcher


endif
	#cargo install --git https://github.com/nervosnetwork/ckb-binary-patcher.git --rev b9489de4b3b9d59bc29bce945279bc6f28413113
	#cargo install --path deps/ckb-binary-patcher


all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make all CFLAGS='$(CFLAGS)'"

debug-test: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make debug-all CFLAGS='$(CFLAGS)'"
	./tool/ckb-binary-patcher -i ./build/debug/tron_sign.so -o ./build/debug/tron_sign.so.patcher
	./tool/ckb-binary-patcher -i ./build/debug/eth_sign.so -o ./build/debug/eth_sign.so.patcher
	./tool/ckb-binary-patcher -i ./build/debug/ckb_sign.so -o ./build/debug/ckb_sign.so.patcher
	./tool/ckb-binary-patcher -i ./build/debug/ed25519_sign.so -o ./build/debug/ed25519_sign.so.patcher
	./tool/ckb-binary-patcher -i ./build/debug/ckb_multi_sign.so -o ./build/debug/ckb_multi_sign.so.patcher
	./tool/ckb-binary-patcher -i ./build/debug/doge_sign.so -o ./build/debug/doge_sign.so.patcher
	./tool/ckb-binary-patcher -i ./build/debug/webauthn_sign.so -o ./build/debug/webauthn_sign.so.patcher

release-test: ${PROTOCOL_HEADER}
	./tool/ckb-binary-patcher -i eth_sign.so.release -o ./build/release/eth_sign.so
	./tool/ckb-binary-patcher -i tron_sign.so.release -o ./build/release/tron_sign.so
	./tool/ckb-binary-patcher -i ckb_sign.so.release -o ./build/release/ckb_sign.so
	./tool/ckb-binary-patcher -i ed25519_sign.so.release -o ./build/release/ed25519_sign.so
	./tool/ckb-binary-patcher -i ckb_multi_sign.so.release -o ./build/release/ckb_multi_sign.so
	./tool/ckb-binary-patcher -i doge_sign.so.release -o ./build/release/doge_sign.so
	./tool/ckb-binary-patcher -i webauthn_sign.so.release -o ./build/release/webauthn_sign.so

debug-all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make debug-all CFLAGS='$(CFLAGS)'"

all: release-all
release-all: $(filter release_%, $(contract_entry_targets)) $(filter release_%, $(dyn_lib_targets)) $(filter release_%, $(webauthn_lib_targets))
debug-all: DEBUG_FLAGS = -DCKB_C_STDLIB_PRINTF
debug-all: $(filter debug_%, $(contract_entry_targets)) $(filter debug_%, $(dyn_lib_targets)) $(filter debug_%, $(webauthn_lib_targets))

# Add DEBUG flags, if target is release, the DEBUG_FLAGS is empty
debug_%: DEBUG_FLAGS = -DCKB_C_STDLIB_PRINTF

# Target aliases
$(contract_entry) $(dyn_libs): %: release_%

# Target to actual output file
$(filter debug_%, $(contract_entry_targets)): debug_%: build/debug/%
$(filter release_%, $(contract_entry_targets)): release_%: build/release/%

# Specify output file dependencies
$(filter build/debug/%, $(contract_entry_files)): build/debug/%: c/%.c ckb-binary-patcher
	@mkdir -p build/debug
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -o $@ $<
	#ckb-binary-patcher -i $@ -o $@
$(filter build/release/%, $(contract_entry_files)): build/release/%: c/%.c ckb-binary-patcher
	@mkdir -p build/release
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -o $@ $<
	#ckb-binary-patcher -i $@ -o $@

# Target to actual output file
$(filter debug_%, $(dyn_lib_targets)): debug_%: build/debug/%.so
$(filter release_%, $(dyn_lib_targets)): release_%: build/release/%.so

# Specify output file dependencies
$(filter build/debug/%, $(dyn_lib_files)): build/debug/%.so: c/%.c ckb-binary-patcher
	@mkdir -p build/debug > /dev/null
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<
	#ckb-binary-patcher -i $@ -o $@
$(filter build/release/%, $(dyn_lib_files)): build/release/%.so: c/%.c ckb-binary-patcher
	@mkdir -p build/release > /dev/null
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<
	ckb-binary-patcher -i $@ -o $@

#$(filter build/debug/%, $(dyn_lib_files)): patch-debug/*.so: build/debug/%.so
#	@ckb-binary-patcher -i $< -o $<

# Target to actual output file
$(filter debug_%, $(webauthn_lib_targets)) : debug_%: build/debug/%.so
$(filter release_%, $(webauthn_lib_targets)) : release_%: build/release/%.so

$(filter build/debug/%, $(webauthn_lib_files)) : build/debug/%.so: c/%.c libecc ckb-binary-patcher c/webauthn.syms
	$(CC) $(CFLAGS) $(CFLAGS_LINK_TO_LIBECC) $(LDFLAGS) $(DEBUG_FLAGS) -o $@ -D__SHARED_LIBRARY__ -pie -Wl,--dynamic-list c/webauthn.syms $< $(SECP256R1_DEP) $(LIBECC_PATH)/src/external_deps/rand.c $(LIBECC_PATH)/src/external_deps/print.c
	$(OBJCOPY) --strip-all $@

$(filter build/release/%, $(webauthn_lib_files)) : build/release/%.so: c/%.c libecc ckb-binary-patcher c/webauthn.syms
	$(CC) $(CFLAGS) $(CFLAGS_LINK_TO_LIBECC) $(LDFLAGS) -o $@ -D__SHARED_LIBRARY__ -pie -Wl,--dynamic-list c/webauthn.syms $< $(SECP256R1_DEP) $(LIBECC_PATH)/src/external_deps/rand.c $(LIBECC_PATH)/src/external_deps/print.c
	$(OBJCOPY) --strip-all $@

libecc :
	make -C ${LIBECC_PATH} LIBECC_WITH_LL_U256_MONT=1 CC=${CC} LD=${LD} CFLAGS="$(CFLAGS_LIBECC)"

# all-via-docker: ${PROTOCOL_HEADER}
# 	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make all"
# 	./tool/ckb-binary-patcher -i eth_sign.so.release -o ./build/release/eth_sign.so
# 	./tool/ckb-binary-patcher -i tron_sign.so.release -o ./build/release/tron_sign.so
# 	./tool/ckb-binary-patcher -i ckb_sign.so.release -o ./build/release/ckb_sign.so
# 	./tool/ckb-binary-patcher -i ed25519_sign.so.release -o ./build/release/ed25519_sign.so
# 	./tool/ckb-binary-patcher -i ckb_multi_sign.so.release -o ./build/release/ckb_multi_sign.so
# 	./tool/ckb-binary-patcher -i doge_sign.so.release -o ./build/release/doge_sign.so
# 	cp dispatch.release ./build/release/dispatch

# debug-all-via-docker: ${PROTOCOL_HEADER}
# 	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make debug_all"
# 	rm build/debug/*
# 	./tool/ckb-binary-patcher -i tron_sign.so.debug -o ./build/debug/tron_sign.so
# 	./tool/ckb-binary-patcher -i eth_sign.so.debug -o ./build/debug/eth_sign.so
# 	./tool/ckb-binary-patcher -i ckb_sign.so.debug -o ./build/debug/ckb_sign.so
# 	./tool/ckb-binary-patcher -i ed25519_sign.so.debug -o ./build/debug/ed25519_sign.so
# 	./tool/ckb-binary-patcher -i ckb_multi_sign.so.debug -o ./build/debug/ckb_multi_sign.so
# 	./tool/ckb-binary-patcher -i doge_sign.so.debug -o ./build/debug/doge_sign.so
# 	cp dispatch.debug ./build/debug/dispatch
# 	#cp ./build/debug/dispatch /mnt/ckb/das-sandbox-testnet2/contracts/dispatch
# 	# cp ./build/debug/* /home/jason/das/run-test/j-contract
# 	#cp ./build/debug/* /mnt/ckb/das-sandbox-mainnet/contracts
# 	#cp ./build/debug/dispatch ubuntu_root:/mnt/ckb/das-sandbox-mainnet/contracts/dispatch
# 	#scp ./build/debug/dispatch ubuntu_root:/mnt/ckb/das-sandbox-testnet2/contracts/dispatch
# 	#scp ./build/debug/dispatch ubuntu_root:/mnt/ckb/das-sandbox-mainnet/contracts/dispatch

# all: dispatch.release eth_sign.so.release ckb_sign.so.release tron_sign.so.release ed25519_sign.so.release ckb_multi_sign.so.release doge_sign.so.release

# debug_all: dispatch.debug eth_sign.so.debug ckb_sign.so.debug tron_sign.so.debug ed25519_sign.so.debug ckb_multi_sign.so.debug doge_sign.so.debug

# dispatch.debug: dispatch.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -o $@ $<

# dispatch.release: dispatch.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# ckb_sign.so.debug: ckb_sign.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<

# ckb_sign.so.release: ckb_sign.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $<

# tron_sign.so.debug: tron_sign.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<

# tron_sign.so.release: tron_sign.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $<

# eth_sign.so.debug: eth_sign.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<

# eth_sign.so.release: eth_sign.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $<

# ed25519_sign.so.debug: ed25519_sign.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<

# ed25519_sign.so.release: ed25519_sign.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $<

# ckb_multi_sign.so.debug: ckb_multi_sign.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<

# ckb_multi_sign.so.release: ckb_multi_sign.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $<

# doge_sign.so.debug: doge_sign.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<

# doge_sign.so.release: doge_sign.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $<

${PROTOCOL_HEADER}: ${PROTOCOL_SCHEMA}
	${MOLC} --language c --schema-file $< > $@

${PROTOCOL_SCHEMA}:
	curl -L -o $@ ${PROTOCOL_URL}
