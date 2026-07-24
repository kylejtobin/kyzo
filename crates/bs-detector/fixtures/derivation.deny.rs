impl S {
    fn bump(&self) {
        unsafe {
            *(self as *const Self as *mut u8) = 0;
        }
    }
}
