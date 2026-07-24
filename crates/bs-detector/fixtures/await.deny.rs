impl S {
    fn get(&self) -> u64 {
        async fn inner() {}
        // `.await` site inside a sync derivation-shaped method.
        let _ = async { 1u64 }.await;
        0
    }
}
