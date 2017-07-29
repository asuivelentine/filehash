use std::ffi::OsString;

pub struct Filehash {
    file: OsString,
    hash: Option<bool>
}

pub enum Hash {
    Xxhash,
    Bcrypt,
    Bsdi,
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Unix
}

impl Filehash {
    pub fn new(file: OsString) -> Filehash {
        Filehash {
            file: file,
            hash: None
        }
    }

    pub fn with_hash(mut self, hash: Hash) -> Filehash {
        self.hash = Some(true);
        self
    }

    pub fn hash(self) {
        println!("Todo");
    }
}


#[cfg(test)]
mod tests {
    use super::{Filehash, Hash};

    #[test]
    fn new() {
        let file = OsString::from("/bin/bash");

        let fh = Filehash::new(file);
    }
}

