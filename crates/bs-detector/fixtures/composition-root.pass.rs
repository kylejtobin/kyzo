struct App {
    port: u64,
}
impl App {
    fn new() -> Self {
        App { port: 0 }
    }
    fn run(self) {}
}
fn main() {
    let app = App::new();
    app.run()
}
