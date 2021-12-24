# DAS LOCK

A dispatch contract and serveral dynamic libs.

## Usage

### Compile


First, do some warm up
``` sh
git submodule update --init --recursive
cd shared-lib/deps/secp256k1
./autogen.sh
# module-recovery for pre_g
# endomorphism for pre_g_128
# ecmult-static-precomputation for ecmult_static_pre_context.h
./configure --enable-module-recovery --enable-endomorphism --enable-ecmult-static-precomputation
make
```

Then, compile
``` sh
mkdir -p build/debug && mkdir -p build/release
cd shared-lib
make all-via-docker
```


## Issues
When `configure` in deps/secp256k1
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
