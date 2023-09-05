use alloc::format;
use crate::debug_log;

use das_proc_macro::test_level;

#[cfg(test)]
pub trait Testable {
    fn run(&self) -> ();
}

#[cfg(test)]
impl<T> Testable for T
    where T: Fn()
{
    fn run(&self) {
        //It is a static str, generated at compile time, so cannot move to my_runner.
        debug_log!("\t{}", core::any::type_name::<T>());
        self();
    }

}

/*
    The test runner is the entry point for the test framework.
    But the main is test_main in src/main.rs. It's similar to the test framework in Rust std.
    The test framework will collect functions marked with #[test_case] and then pass them into my_runner.
 */
#[cfg(test)]
pub fn my_runner(tests: &[&dyn Testable]) {

    //debug log to show compile features
    if cfg!(feature = "test_single") {
        debug_log!("test_single");
    }else if cfg!(feature = "test_partial") {
        debug_log!("test_partial");
    }else if cfg!(feature = "test_dev") {
        debug_log!("test_dev");
    }else {
        debug_log!("test_all");
    }

    let total = tests.len();
    debug_log!("Running {} tests", total);

    let mut count = 1;
    for test in tests {
        let progress = format!("({}/{}) ", count, total);
        debug_log!("{} Testing", progress);
        test.run();
        debug_log!("{} ✔ Test passed", progress);
        count += 1;
    }
}
// # Test Levels
//
// - `test_level(0)` means this test will be run all the time.
// - `test_level(1)` means this test will be run when TEST_LEVEL=1, use to debug.
// - `test_level(2)` means this test will be run when TEST_LEVEL=2, use to test transaction.
// - `test_level(3)` means this test will be run when TEST_LEVEL=3, use to test single case.
//
// # Examples
//
// ```
//
// ```
// If you want to test only a certain level, please enable the corresponding features when compiling.
// The default is test_all. Corresponds to test_level(0).
// test_dev: test_level(1)
// test_partial: test_level(2)
// test_single: test_level(3)
#[test_level(0)]
fn it_works_level_0() {
    assert_eq!(2 + 2, 4);
}
#[test_level(1)]
fn it_works_level_1() {
    assert_eq!(2 + 2, 4);
}
#[test_level(2)]
fn it_works_level_2() {
    assert_eq!(2 + 2, 4);
}
#[test_level(3)]
fn it_works_level_3() {
    assert_eq!(2 + 2, 4);
}
// ``` shell
// cargo test --features test_dev --no-run --target risv64gc-unknown-none-elf
// ```


// //Todo: Catching panics is not currently supported, and the test will break if it occurs.
// #[test_level(0)]
// fn test_panic() {
//     panic!("test panic");
// }
