# Overview
The test_level crate provides a custom Rust procedural macro attribute that controls whether to include a test function based on a specified threshold. The threshold is set according to different build configurations, which are specified through Rust feature flags. The macro takes an integer attribute to determine the level at which a test should be included.

# How to Use
To use this macro, attach it to your test functions and pass an integer value that represents the level of the test.

``` rust
Copy code
use test_level::test_level;

#[test_level(2)]
fn my_test_function() {
    // test code
}
```

# Features
* `test-single`: When enabled, sets the threshold to 3.
* `test-partial`: When enabled, sets the threshold to 2.
* `test-dev`: When enabled, sets the threshold to 1.
* `test-all`: When enabled, sets the threshold to 0.

# Implementation Details
## MacroInput struct
A struct that represents the parsed attribute input. It contains a single field value that holds the level specified in the attribute.

## test_level attribute
This is the main attribute macro function. It compares the feature flag set during compilation to the value provided in the attribute. Depending on this comparison, the test function is either included or excluded from the codebase.

# Dependencies
* proc_macro: Required to implement procedural macros in Rust.
* quote: To generate Rust code as a stream of tokens.
* syn: For parsing Rust code.

# Installation
Include it in your Cargo.toml:

```toml
[dependencies]
test_level = "0.1.0"
```

# Limitations
The macro currently supports only test functions, not other types of functions or methods.
The macro assumes that the feature flags are set through cargo features.

# Troubleshooting
If you are getting parsing errors, make sure you pass a valid integer as the attribute to #[test_level].

# Contributing
Feel free to submit PRs or to report issues.

# License
This project is licensed under the MIT license.