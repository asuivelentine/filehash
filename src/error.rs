quick_error! {
    #[derive(Debug)]
    pub enum FilehashError {
        FileNotFound(err: ::std::io::Error) { from() }
        HashError {}
    } 
}
