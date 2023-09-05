#[macro_export]
macro_rules! debug_log {
    ($msg:expr) => {
        ckb_std::syscalls::debug(alloc::format!($msg))
    };
    ($msg:expr, $($arg:tt)*) => {
        ckb_std::syscalls::debug(alloc::format!($msg, $($arg)*))
    };
}


#[macro_export]
macro_rules! impl_unwrap {
    ($variant:ident, $method_name:ident, $type:ty) => {
        pub fn $method_name(self) -> $type {
            match self {
                LVType::$variant(value) => value,
                _ => panic!(concat!("Called `", stringify!($method_name), "` on a variant that was not ", stringify!($variant))),
            }
        }
    }
}