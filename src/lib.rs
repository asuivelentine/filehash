//! # Filehash
//!
//! Filehash is a small crypto_hash wrapper for files.
//!
//! ```rust
//! use filehash::filehash::{Filehash, Hash};
//!
//! fn calculate_hash() -> Vec<u8> {
//!     Filehash::from("/bin/bash")
//!         .with_hash(Hash::Sha512)
//!         .hash()
//!         .unwrap()
//! }
//! ```
//!

#[deny(non_camel_case_types,
       non_snake_case,
       unused_import_braces,
       trivial_numeric_casts,
       unstable_features,
       unused_allocation,
       unused_imports,
       unused_must_use,
       unused_mut,
       unused_qualifications,
       while_true,
       unsafe_code)]

extern crate crypto_hash;
#[macro_use] extern crate quick_error;

/// Mod for filehashing.
pub mod filehash;
/// An error that occured while hashing the file.
pub mod error;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
