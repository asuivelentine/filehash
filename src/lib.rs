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
extern crate twox_hash;

pub mod filehash;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
