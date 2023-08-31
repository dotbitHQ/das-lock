#[macro_export]
macro_rules! debug_log {
    ($msg:expr) => {
        ckb_std::syscalls::debug(alloc::format!($msg))
    };
    ($msg:expr, $($arg:tt)*) => {
        ckb_std::syscalls::debug(alloc::format!($msg, $($arg)*))
    };
}
