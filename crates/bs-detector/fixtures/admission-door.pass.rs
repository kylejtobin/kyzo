struct T {
    a: u64,
}
impl T {
    fn new() -> Result<Self, u8> {
        Ok(T { a: 0 })
    }
}
