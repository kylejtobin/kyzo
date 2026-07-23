struct T {
    a: u64,
}
impl T {
    fn read(&self) -> u64 {
        let mut x = 0;
        x = self.a;
        x
    }
}
