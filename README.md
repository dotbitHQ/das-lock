# DAS LOCK

A dispatch contract and some dynamic libraries.

## Overview
This project is a Rust and C hybrid project that targets the `riscv64-unknown-linux-gnu` platform. It uses Rust for the contract entry (`dispatch`) and C for dynamic libraries (`ckb_sign`, `tron_sign`, etc). The Makefile handles the build process, enabling development through both native and Docker environments. The project also depends on the Nervos Network CKB blockchain protocol and several cryptography libraries.

## Dependencies
* Docker: [dotbitteam/ckb-dev-all-in-one](https://hub.docker.com/r/dotbitteam/ckb-dev-all-in-one)
* Rust Toolchain: Targeting riscv64imac-unknown-none-elf
* C Toolchain: Targeting riscv64-unknown-linux-gnu
* ckb-binary-patcher: [ckb/ckb-binary-patcher](https://github.com/nervosnetwork/ckb-binary-patcher)
* libecc: [dotbitteam/libecc](https://github.com/dotbitHQ/libecc-riscv-optimized)
* secp256k1


## Features
* Build for multiple net types (default is `testnet2`)
* Optimize and strip binaries
* Debug and Release build types
* Control build flags via environment variables
* Docker environment for isolated building
* Compile contracts and dynamic libraries with security features


## Build Instructions
1. Clone the repository:
    ```shell
    git clone https://github.com/dotbitHQ/das-lock
   ```
2. Initialize environment and submodules:
    ```shell
    make init-build-env
    ```
3. Pull the Docker image:
    ```shell
    make pull-docker-image
    ```
4. Build all contracts and libraries:
    ```shell
    make debug-all-via-docker # or make all-via-docker
    ```
5. Copy the generated binaries to the other directory:
    ```shell
    cp -r build/debugs/* /path/to/other/directory
    ```

## Configuration
The `Makefile` supports the following environment variables:

* `NET_TYPE`: The type of blockchain network, default is `testnet2`.
    ```shell
    make debug-all-via-docker NET_TYPE=mainnet
    ```
* `CFLAGS`: Flags for the C compiler.

## License
[License](LICENSE)
