pub mod generate_sighash_all;

use crate::debug_log;
use crate::error::Error;
pub use blake2b_rs::{Blake2b, Blake2bBuilder};

pub const CKB_PERSONALIZATION: &[u8] = b"ckb-default-hash";
pub fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(CKB_PERSONALIZATION)
        .build()
}

pub fn bytes_to_u32_le(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    Some(
        ((bytes[3] as u32) << 24)
            | ((bytes[2] as u32) << 16)
            | ((bytes[1] as u32) << 8)
            | (bytes[0] as u32),
    )
}

pub fn check_num_boundary(num: u32, min: u32, max: u32) -> Result<(), Error> {
    if num < min || num > max {
        debug_log!("num out of bound, expected [{}, {}], got {}", min, max, num);
        return Err(Error::NumOutOfBound);
    }
    Ok(())
}
