use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};

use crypto_hash::{Hasher, Algorithm};

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
}

