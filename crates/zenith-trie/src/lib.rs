#![no_std]
#[cfg(feature = "std")]
extern crate std;

#[cfg(any(feature = "alloc", feature = "std"))]
extern crate alloc;

#[cfg(not(any(feature = "alloc", feature = "std")))]
compile_error!("zenith-trie requires either 'alloc' or 'std' feature");

pub mod trie;
