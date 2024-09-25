# Compiler & tools settings
TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy

DEBUG_FLAGS := $(empty)
CFLAGS ?= -Os -fPIC -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -I . -I deps/ckb-c-stdlib -I deps/ckb-c-stdlib/libc -I deps/ckb-c-stdlib/molecule -I deps/secp256k1/src -I deps/secp256k1  -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
RUST_FLAGS = -Z pre-link-arg=-zseparate-code -Z pre-link-arg=-zseparate-loadable-segments
RUST_TARGET = riscv64imac-unknown-none-elf

# Libraries and their path
LIBECC_PATH := deps/libecc-riscv-optimized
SECP256R1_DEP := ${LIBECC_PATH}/build/libarith.a ${LIBECC_PATH}/build/libec.a ${LIBECC_PATH}/build/libsign.a
CFLAGS_LIBECC := -fPIC -O3 -fno-builtin -DUSER_NN_BIT_LEN=256 -DWORDSIZE=64 -DWITH_STDLIB -DWITH_BLANK_EXTERNAL_DEPENDENCIES -DCKB_DECLARATION_ONLY -DWITH_LL_U256_MONT
CFLAGS_LINK_TO_LIBECC := -fno-builtin -DWORDSIZE=64 -DWITH_STDLIB -DWITH_BLANK_EXTERNAL_DEPENDENCIES -fno-builtin-printf -I ${LIBECC_PATH}/src -I ${LIBECC_PATH}/src/external_deps

# Docker settings
BUILDER_DOCKER := dylanweb3/ckb-dev-all-in-one:0.0.5
CODE_DIR_DOCKER := /code

# Define a function for Docker run
define DOCKER_RUN_CMD
	docker run --rm \
	-v `pwd`:/code \
	-v ~/.gitconfig:/root/.gitconfig:ro \
	-v ~/.cargo:/root/.cargo \
	-e NET_TYPE=${NET_TYPE} \
	${BUILDER_DOCKER} bash -c
endef

PROTOCOL_HEADER := c/protocol.h
PROTOCOL_SCHEMA := c/blockchain.mol
PROTOCOL_VERSION := d75e4c56ffa40e17fd2fe477da3f98c5578edcd1
PROTOCOL_URL := https://raw.githubusercontent.com/nervosnetwork/ckb/${PROTOCOL_VERSION}/util/types/schemas/blockchain.mol
#note: compile ckb-binary-patcher in docker container
CKB_BINARY_PATCHER_PATH = ./tools/ckb-binary-patcher/target/release/ckb-binary-patcher

# Target aliases
dyn_libs := ckb_sign tron_sign eth_sign ed25519_sign ckb_multi_sign doge_sign btc_sign
webauthn_lib := webauthn_sign
NET_TYPE ?= testnet2 #note: use testnet2 by default

all_libs := $(dyn_libs) $(webauthn_lib)
dyn_lib_targets = $(foreach file, $(dyn_libs), release_$(file) debug_$(file))
dyn_lib_files = $(foreach file, $(dyn_libs), build/release/$(file).so build/debug/$(file).so)

webauthn_lib_targets = $(foreach file, $(webauthn_lib), release_$(file) debug_$(file))
webauthn_lib_files = $(foreach file, $(webauthn_lib), build/release/$(file).so build/debug/$(file).so)


debug-all-via-docker: ${PROTOCOL_HEADER} install-ckb-binary-patcher
	@mkdir -p build/debug
	#make debug-all
	${DOCKER_RUN_CMD} "cd ${CODE_DIR_DOCKER} && make debug-all CFLAGS='$(CFLAGS)'"

all-via-docker: ${PROTOCOL_HEADER} install-ckb-binary-patcher
	@mkdir -p build/release
	#make all
	@${DOCKER_RUN_CMD} "cd ${CODE_DIR_DOCKER} && make all CFLAGS='$(CFLAGS)'"

debug-all: DEBUG_FLAGS = -DCKB_C_STDLIB_PRINTF
debug-all: $(filter debug_%, $(dyn_lib_targets)) $(filter debug_%, $(webauthn_lib_targets))

all: release-all
release-all: $(filter release_%, $(dyn_lib_targets)) $(filter release_%, $(webauthn_lib_targets))

# Add DEBUG flags, if target is release, the DEBUG_FLAGS is empty
debug_%: DEBUG_FLAGS = -DCKB_C_STDLIB_PRINTF

# Target aliases
$(dyn_libs): %: release_%

# Compile the dynamic libraries
# Target to actual output file
$(filter debug_%, $(dyn_lib_targets)): debug_%: build/debug/%.so
$(filter release_%, $(dyn_lib_targets)): release_%: build/release/%.so

# Specify output file dependencies
$(filter build/debug/%, $(dyn_lib_files)): build/debug/%.so: c/%.c
	@echo "make $@"
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<
	@#note: ckb-binary-patcher will read the file into memory, modify it and then overwrite it, so don't worry.
	${CKB_BINARY_PATCHER_PATH} -i $@ -o $@
$(filter build/release/%, $(dyn_lib_files)): build/release/%.so: c/%.c
	@echo "make $@"
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -shared -o $@ $<
	${CKB_BINARY_PATCHER_PATH} -i $@ -o $@

#$(filter build/debug/%, $(dyn_lib_files)): patch-debug/*.so: build/debug/%.so
#	@ckb-binary-patcher -i $< -o $<

# Target to actual output file
$(filter debug_%, $(webauthn_lib_targets)) : debug_%: build/debug/%.so
$(filter release_%, $(webauthn_lib_targets)) : release_%: build/release/%.so

$(filter build/debug/%, $(webauthn_lib_files)) : build/debug/%.so: c/%.c libecc c/webauthn.syms
	@echo "make $@"
	$(CC) $(CFLAGS) $(CFLAGS_LINK_TO_LIBECC) $(LDFLAGS) $(DEBUG_FLAGS) -o $@ -D__SHARED_LIBRARY__ -pie -Wl,--dynamic-list c/webauthn.syms $< $(SECP256R1_DEP) $(LIBECC_PATH)/src/external_deps/rand.c $(LIBECC_PATH)/src/external_deps/print.c
	$(OBJCOPY) --strip-all $@

$(filter build/release/%, $(webauthn_lib_files)) : build/release/%.so: c/%.c libecc  c/webauthn.syms
	@echo "make $@"
	$(CC) $(CFLAGS) $(CFLAGS_LINK_TO_LIBECC) $(LDFLAGS) -o $@ -D__SHARED_LIBRARY__ -pie -Wl,--dynamic-list c/webauthn.syms $< $(SECP256R1_DEP) $(LIBECC_PATH)/src/external_deps/rand.c $(LIBECC_PATH)/src/external_deps/print.c
	$(OBJCOPY) --strip-all $@

libecc :
	#make libecc
	@#note: If you run this command alone, you need to install riscv-toolchain
	make -C ${LIBECC_PATH} LIBECC_WITH_LL_U256_MONT=1 CC=${CC} LD=${LD} CFLAGS="$(CFLAGS_LIBECC)"


${PROTOCOL_HEADER}: ${PROTOCOL_SCHEMA}
	${MOLC} --language c --schema-file $< > $@

${PROTOCOL_SCHEMA}:
	curl -L -o $@ ${PROTOCOL_URL}

CKB_BINARY_PATCHER_PATH = ${CODE_DIR_DOCKER}/tools/ckb-binary-patcher/target/release/ckb-binary-patcher

install-ckb-binary-patcher:
	# Check if tools/ckb-binary-patcher exists
	@if [ ! -d "tools/ckb-binary-patcher" ]; then \
		echo "ckb-binary-patcher not found. Initializing submodule..."; \
		git submodule update --init; > /dev/null 2>&1; \
	fi
	# Check if have cargo installed
	@if [ -z "$(shell which cargo 2>/dev/null)" ]; then \
		echo "cargo could not be found. Please install Rust and Cargo."; \
		exit 1; \
	fi

	#Compile ckb-binary-patcher
	@${DOCKER_RUN_CMD} "cd ${CODE_DIR_DOCKER}/tools/ckb-binary-patcher && \
		cargo build --release 2>&1 >/dev/null"
	#Compile success

init-submodule:
	@echo "init submodule"
	git submodule update --init --recursive

build-secp256r1:
	@echo "build secp256r1"
	cd deps/secp256k1 && \
	./autogen.sh && \
	./configure \
	--enable-module-recovery \
	--enable-experimental \
	--with-bignum=no \
	--with-asm=no \
	--enable-endomorphism \
	--enable-ecmult-static-precomputation && \
	make -j

build-libecc:
	@echo "build libecc"
	${DOCKER_RUN_CMD} "cd ${CODE_DIR_DOCKER} && make libecc"

init-build-env: init-submodule build-secp256r1 build-libecc
	@echo "init build env"

pull-docker-image:
	docker pull ${BUILDER_DOCKER}

clean:
	cd das-lock-lib && cargo clean
	#cd deps/libecc-riscv-optimized && make clean
	rm -rf build/release/*
	rm -rf build/debug/*
	cargo clean
.PHONY: clean debug-all-via-docker all-via-docker debug-all release-all init-build-env pull-docker-image
