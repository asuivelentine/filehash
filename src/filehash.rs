use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Read;

pub struct Filehash {
    file: OsString,
    hash: Option<Hash>
}

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

    pub fn hash(self) -> Result<String, ()> {
        try!(self.read_to_u8());

        Ok(String::from("hash"))
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

