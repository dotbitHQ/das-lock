# Overview
This project is a Rust-based command line tool designed to automate various tasks related to a blockchain or cryptographic application. It involves initializing C dependencies, building libraries, and integrating built files into the Rust environment.

The code performs the following operations:

1. Initializes git submodules and updates them recursively.
2. Builds the secp256k1 library.
3. Builds the libecc library.
4. Builds the dispatch library.
5. Copies built files into the Rust target directory.
6. Generates a Rust module that contains static binary and hash data.


# Dependencies
* Rust: Make sure you have Rust installed.
* Blake2b: For hashing operations.
* Git: For submodule initialization.
* C Dependencies: Make sure you have the required C dependencies installed.


# How to Run
Run the program using the following command:
```shell
cargo run
```

# Limitations
C build flags are hardcoded into the build process. Consider parameterizing them for more flexibility.

# Troubleshooting

## Build Failures
If you encounter any build failures, make sure all C dependencies are correctly installed and initialized.

## Hashing Errors
Ensure that the Blake2b library is correctly installed and updated.

# Contribution
Feel free to submit PRs or to report issues. This project is open for improvements and additional features.

# License
This project is licensed under the MIT license.

