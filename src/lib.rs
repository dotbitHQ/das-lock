// Dummy rust file for building this project into a crate
pub mod contracts {
    include!(concat!(env!("OUT_DIR"), "/contracts/mod.rs"));
}