# DAS LOCK

A dispatch contract and serveral dynamic libs.

## Usage

### Compile


First, do some warm up
``` sh
git submodule update --init --recursive
cd deps/secp256k1
./autogen.sh
# module-recovery for pre_g
# endomorphism for pre_g_128
# ecmult-static-precomputation for ecmult_static_pre_context.h
# with-bignum 
./configure --with-bignum=no --with-asm=no --enable-module-recovery --enable-endomorphism --enable-ecmult-static-precomputation
make
```

Then, compile
``` sh
mkdir -p build/debug && mkdir -p build/release
# debug
make debug-all-via-docker
```


## Option


## Issues
### 1. When `configure` in deps/secp256k1
``` sh
# cat config.log
clang: error: argument to '-V' is missing (expected 1 value)
or
clang: error: linker command failed with exit code 1 (use -v to see invocation)
```
Try below before `configure`
``` sh
export SDKROOT=$(xcrun --sdk macosx --show-sdk-path)
```

### 2. When `make debug-all-via-docker`
In some machine environments, the following error may be reported.
```shell
./tool/ckb-binary-patcher: 1: Syntax error: "(" unexpected
```
You need to recompile `ckb-binary-patcher` , refer to the following command.
```shell
cd build/
git clone https://github.com/nervosnetwork/ckb-binary-patcher
cd ckb-binary-patcher
cargo build --release 
cp ./target/release/ckb-binary-patcher ../../tool
```
