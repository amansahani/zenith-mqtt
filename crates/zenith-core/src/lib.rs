#![no_std]
#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "alloc")]
extern crate alloc;

pub mod packet;
pub mod error;
pub mod wire;
pub mod utf8;
pub mod properties;
