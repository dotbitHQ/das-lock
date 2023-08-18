# DAS LOCK

A dispatch contract and some dynamic libraries.

## Usage

### Compile

The compilation of the current code repository requires the riscv toolchain, so docker needs to be pre-installed.
There are currently two ways to compile:
#### A. Through the buildscript in the root directory of the warehouse
1. Start the corresponding docker image
```shell
bash buildscript start -b 
```
2. Compile the source code
```shell
bash buildscript build
```
If you want to compile the release version, please add `--release`
```shell
bash buildscript build --release
```
#### B. Manually compile through makefile
1. Check git warehouse dependencies
```shell
git submodule init update
```
2. Execute make
```shell
make debug-test
```
## Option


## Issues
