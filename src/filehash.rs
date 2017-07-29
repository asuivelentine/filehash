use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};

use crypto_hash::{Hasher, Algorithm};

#[derive(Debug)]
pub struct Filehash {
    file: OsString,
    hash: Option<Hash>
}

#[derive(PartialEq, Debug)]
pub enum Hash {
    Xxhash,
    Md5,
    Sha1,
    Sha256,
    Sha512
}

impl Filehash {
    pub fn new(file: OsString) -> Filehash {
        Filehash {
            file: file,
            hash: None
        }
    }

    pub fn with_hash(mut self, hash: Hash) -> Filehash {
        self.hash = Some(hash);
        self
    }

    pub fn hash(self) -> Result<Vec<u8>, ()> {
        let fileconent = try!(self.read_to_u8());

        let mut hasher = match self.hash {
            Some(Hash::Md5) => Hasher::new(Algorithm::MD5),
            Some(Hash::Sha1) => Hasher::new(Algorithm::SHA1),
            Some(Hash::Sha256) => Hasher::new(Algorithm::SHA256), 
            Some(Hash::Sha512) => Hasher::new(Algorithm::SHA512),
            _ => Hasher::new(Algorithm::MD5),
        };

        try!(hasher
            .write_all(fileconent.as_slice())
            .map_err(|_| ()));

        Ok(hasher.finish())
    }

    fn read_to_u8(&self) -> Result<Vec<u8>, ()> {
        let mut content = Vec::<u8>::new();

        let mut f = try!(OpenOptions::new()
            .read(true)
            .create(false)
            .open(&self.file)
            .map_err(|_| ()));

        try!(f.read_to_end(&mut content)
            .map_err(|_| ()));

        Ok(content)
    }
}


#[cfg(test)]
mod tests {
    use super::{Filehash, Hash};
    use std::ffi::OsString;

    #[test]
    fn new() {
        let file = OsString::from("/bin/bash");
        let fh = Filehash::new(file);

        assert_eq!(fh.file, OsString::from("/bin/bash"));
        assert_eq!(fh.hash, None);
    }

    #[test]
    fn md5_hash() {
        let file = OsString::from("./testfiles/main.c");
        let hash = Filehash::new(file)
            .with_hash(Hash::Md5)
            .hash();

        let correct = vec!(0x0e_u8, 0x5c, 0xb0, 0x56, 0x61, 0xe0, 0xb4, 0x30, 0xca, 0x6c, 0x82,
                           0x25, 0x6d, 0x58, 0xcd, 0xc4);

        assert_eq!(hash, Ok(correct));
    }

    #[test]
    fn sha1_hash() {
        let file = OsString::from("./testfiles/main.c");
        let hash = Filehash::new(file)
            .with_hash(Hash::Sha1)
            .hash();

        let correct = vec!(0xd1_u8, 0xd8, 0xb8, 0x60, 0x2d, 0x9e, 0x45, 0xa9, 0xbe, 0xc1, 0x6e,
                           0x88, 0x27, 0x26, 0x13, 0xbc, 0xc4, 0xb5, 0xe2, 0x46);

        assert_eq!(hash, Ok(correct));
    }

    #[test]
    fn sha256_hash() {
        let file = OsString::from("./testfiles/main.c");
        let hash = Filehash::new(file)
            .with_hash(Hash::Sha256)
            .hash();

        let correct = vec!(0x42_u8, 0xe7, 0x07, 0x56, 0x9a, 0x7d, 0x31, 0xd1, 0xb4, 0x8f, 0xce,
                           0x92, 0x97, 0x25, 0x8a, 0x19, 0x90, 0x82, 0x6a, 0x79, 0xfb, 0x9e, 0xb5,
                           0x97, 0x29, 0x99, 0x2d, 0x04, 0x16, 0x45, 0x98, 0x47);

        assert_eq!(hash, Ok(correct));
    }

    #[test]
    fn sha512_hash() {
        let file = OsString::from("./testfiles/main.c");
        let hash = Filehash::new(file)
            .with_hash(Hash::Sha512)
            .hash();

        let correct = vec!(0x46_u8, 0xbf, 0x0a, 0x86, 0xdc, 0x81, 0x50, 0xe4, 0xc4, 0xf0, 0x51,
                           0xe5, 0x9c, 0xad, 0x22, 0xae, 0xb4, 0xe3, 0xcc, 0x1b, 0xdd, 0xf9, 0xda,
                           0xaa, 0xb3, 0x2f, 0xeb, 0xfc, 0x1a, 0xde, 0x4b, 0x12, 0x7f, 0x96, 0x0d,
                           0x14, 0x6e, 0x72, 0x72, 0x4b, 0x53, 0x49, 0x9a, 0x3a, 0xa0, 0xdc, 0xf8,
                           0x63, 0xf1, 0xd6, 0x49, 0x61, 0x94, 0x6a, 0x3b, 0x85, 0x2d, 0xf3, 0xfc,
                           0xa4, 0x96, 0x93, 0xc2, 0xdf);

        assert_eq!(hash, Ok(correct));
    }
}

