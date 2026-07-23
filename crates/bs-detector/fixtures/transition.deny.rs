struct T {
    a: [u64; 2],
}
impl T {
    fn step(&mut self) {
        self.a[0] = 1;
    }
}
