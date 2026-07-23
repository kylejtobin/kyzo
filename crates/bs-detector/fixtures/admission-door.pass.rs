enum DoorError {
    Empty,
}
struct T {
    a: u64,
}
impl T {
    fn new() -> Result<Self, DoorError> {
        Ok(T { a: 0 })
    }
}
